
#define pr_fmt(fmt) "PM: " fmt

#include <linux/module.h>
#include <linux/file.h>
#include <linux/delay.h>
#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pm.h>
#include <linux/slab.h>
#include <linux/lzo.h>
#include <linux/vmalloc.h>
#include <linux/cpumask.h>
#include <linux/atomic.h>
#include <linux/kthread.h>
#include <linux/crc32.h>
#include <linux/ktime.h>

#include "power.h"

#define HIBERNATE_SIG	"S1SUSPEND"

u32 swsusp_hardware_signature;

static bool clean_pages_on_read;
static bool clean_pages_on_decompress;


#define MAP_PAGE_ENTRIES	(PAGE_SIZE / sizeof(sector_t) - 1)

static inline unsigned long low_free_pages(void)
{
	return nr_free_pages() - nr_free_highpages();
}

static inline unsigned long reqd_free_pages(void)
{
	return low_free_pages() / 2;
}

struct swap_map_page {
	sector_t entries[MAP_PAGE_ENTRIES];
	sector_t next_swap;
};

struct swap_map_page_list {
	struct swap_map_page *map;
	struct swap_map_page_list *next;
};


struct swap_map_handle {
	struct swap_map_page *cur;
	struct swap_map_page_list *maps;
	sector_t cur_swap;
	sector_t first_sector;
	unsigned int k;
	unsigned long reqd_free_pages;
	u32 crc32;
};

struct swsusp_header {
	char reserved[PAGE_SIZE - 20 - sizeof(sector_t) - sizeof(int) -
	              sizeof(u32) - sizeof(u32)];
	u32	hw_sig;
	u32	crc32;
	sector_t image;
	unsigned int flags;	/* Flags to pass to the "boot" kernel */
	char	orig_sig[10];
	char	sig[10];
} __packed;

static struct swsusp_header *swsusp_header;


struct swsusp_extent {
	struct rb_node node;
	unsigned long start;
	unsigned long end;
};

static struct rb_root swsusp_extents = RB_ROOT;

static int swsusp_extents_insert(unsigned long swap_offset)
{
	struct rb_node **new = &(swsusp_extents.rb_node);
	struct rb_node *parent = NULL;
	struct swsusp_extent *ext;

	/* Figure out where to put the new node */
	while (*new) {
		ext = rb_entry(*new, struct swsusp_extent, node);
		parent = *new;
		if (swap_offset < ext->start) {
			/* Try to merge */
			if (swap_offset == ext->start - 1) {
				ext->start--;
				return 0;
			}
			new = &((*new)->rb_left);
		} else if (swap_offset > ext->end) {
			/* Try to merge */
			if (swap_offset == ext->end + 1) {
				ext->end++;
				return 0;
			}
			new = &((*new)->rb_right);
		} else {
			/* It already is in the tree */
			return -EINVAL;
		}
	}
	/* Add the new node and rebalance the tree. */
	ext = kzalloc(sizeof(struct swsusp_extent), GFP_KERNEL);
	if (!ext)
		return -ENOMEM;

	ext->start = swap_offset;
	ext->end = swap_offset;
	rb_link_node(&ext->node, parent, new);
	rb_insert_color(&ext->node, &swsusp_extents);
	return 0;
}


sector_t alloc_swapdev_block(int swap)
{
	unsigned long offset;

	offset = swp_offset(get_swap_page_of_type(swap));
	if (offset) {
		if (swsusp_extents_insert(offset))
			swap_free(swp_entry(swap, offset));
		else
			return swapdev_block(swap, offset);
	}
	return 0;
}


void free_all_swap_pages(int swap)
{
	struct rb_node *node;

	while ((node = swsusp_extents.rb_node)) {
		struct swsusp_extent *ext;
		unsigned long offset;

		ext = rb_entry(node, struct swsusp_extent, node);
		rb_erase(node, &swsusp_extents);
		for (offset = ext->start; offset <= ext->end; offset++)
			swap_free(swp_entry(swap, offset));

		kfree(ext);
	}
}

int swsusp_swap_in_use(void)
{
	return (swsusp_extents.rb_node != NULL);
}


static unsigned short root_swap = 0xffff;
static struct block_device *hib_resume_bdev;

struct hib_bio_batch {
	atomic_t		count;
	wait_queue_head_t	wait;
	blk_status_t		error;
	struct blk_plug		plug;
};

static void hib_init_batch(struct hib_bio_batch *hb)
{
	atomic_set(&hb->count, 0);
	init_waitqueue_head(&hb->wait);
	hb->error = BLK_STS_OK;
	blk_start_plug(&hb->plug);
}

static void hib_finish_batch(struct hib_bio_batch *hb)
{
	blk_finish_plug(&hb->plug);
}

static void hib_end_io(struct bio *bio)
{
	struct hib_bio_batch *hb = bio->bi_private;
	struct page *page = bio_first_page_all(bio);

	if (bio->bi_status) {
		pr_alert("Read-error on swap-device (%u:%u:%Lu)\n",
			 MAJOR(bio_dev(bio)), MINOR(bio_dev(bio)),
			 (unsigned long long)bio->bi_iter.bi_sector);
	}

	if (bio_data_dir(bio) == WRITE)
		put_page(page);
	else if (clean_pages_on_read)
		flush_icache_range((unsigned long)page_address(page),
				   (unsigned long)page_address(page) + PAGE_SIZE);

	if (bio->bi_status && !hb->error)
		hb->error = bio->bi_status;
	if (atomic_dec_and_test(&hb->count))
		wake_up(&hb->wait);

	bio_put(bio);
}

static int hib_submit_io(blk_opf_t opf, pgoff_t page_off, void *addr,
			 struct hib_bio_batch *hb)
{
	struct page *page = virt_to_page(addr);
	struct bio *bio;
	int error = 0;

	bio = bio_alloc(hib_resume_bdev, 1, opf, GFP_NOIO | __GFP_HIGH);
	bio->bi_iter.bi_sector = page_off * (PAGE_SIZE >> 9);

	if (bio_add_page(bio, page, PAGE_SIZE, 0) < PAGE_SIZE) {
		pr_err("Adding page to bio failed at %llu\n",
		       (unsigned long long)bio->bi_iter.bi_sector);
		bio_put(bio);
		return -EFAULT;
	}

	if (hb) {
		bio->bi_end_io = hib_end_io;
		bio->bi_private = hb;
		atomic_inc(&hb->count);
		submit_bio(bio);
	} else {
		error = submit_bio_wait(bio);
		bio_put(bio);
	}

	return error;
}

static int hib_wait_io(struct hib_bio_batch *hb)
{
	/*
	wait_event(hb->wait, atomic_read(&hb->count) == 0);
	return blk_status_to_errno(hb->error);
}

static int mark_swapfiles(struct swap_map_handle *handle, unsigned int flags)
{
	int error;

	hib_submit_io(REQ_OP_READ, swsusp_resume_block, swsusp_header, NULL);
	if (!memcmp("SWAP-SPACE",swsusp_header->sig, 10) ||
	    !memcmp("SWAPSPACE2",swsusp_header->sig, 10)) {
		memcpy(swsusp_header->orig_sig,swsusp_header->sig, 10);
		memcpy(swsusp_header->sig, HIBERNATE_SIG, 10);
		swsusp_header->image = handle->first_sector;
		if (swsusp_hardware_signature) {
			swsusp_header->hw_sig = swsusp_hardware_signature;
			flags |= SF_HW_SIG;
		}
		swsusp_header->flags = flags;
		if (flags & SF_CRC32_MODE)
			swsusp_header->crc32 = handle->crc32;
		error = hib_submit_io(REQ_OP_WRITE | REQ_SYNC,
				      swsusp_resume_block, swsusp_header, NULL);
	} else {
		pr_err("Swap header not found!\n");
		error = -ENODEV;
	}
	return error;
}

static int swsusp_swap_check(void)
{
	int res;

	if (swsusp_resume_device)
		res = swap_type_of(swsusp_resume_device, swsusp_resume_block);
	else
		res = find_first_swap(&swsusp_resume_device);
	if (res < 0)
		return res;
	root_swap = res;

	hib_resume_bdev = blkdev_get_by_dev(swsusp_resume_device, FMODE_WRITE,
			NULL);
	if (IS_ERR(hib_resume_bdev))
		return PTR_ERR(hib_resume_bdev);

	res = set_blocksize(hib_resume_bdev, PAGE_SIZE);
	if (res < 0)
		blkdev_put(hib_resume_bdev, FMODE_WRITE);

	return res;
}


static int write_page(void *buf, sector_t offset, struct hib_bio_batch *hb)
{
	void *src;
	int ret;

	if (!offset)
		return -ENOSPC;

	if (hb) {
		src = (void *)__get_free_page(GFP_NOIO | __GFP_NOWARN |
		                              __GFP_NORETRY);
		if (src) {
			copy_page(src, buf);
		} else {
			ret = hib_wait_io(hb); /* Free pages */
			if (ret)
				return ret;
			src = (void *)__get_free_page(GFP_NOIO |
			                              __GFP_NOWARN |
			                              __GFP_NORETRY);
			if (src) {
				copy_page(src, buf);
			} else {
				WARN_ON_ONCE(1);
				hb = NULL;	/* Go synchronous */
				src = buf;
			}
		}
	} else {
		src = buf;
	}
	return hib_submit_io(REQ_OP_WRITE | REQ_SYNC, offset, src, hb);
}

static void release_swap_writer(struct swap_map_handle *handle)
{
	if (handle->cur)
		free_page((unsigned long)handle->cur);
	handle->cur = NULL;
}

static int get_swap_writer(struct swap_map_handle *handle)
{
	int ret;

	ret = swsusp_swap_check();
	if (ret) {
		if (ret != -ENOSPC)
			pr_err("Cannot find swap device, try swapon -a\n");
		return ret;
	}
	handle->cur = (struct swap_map_page *)get_zeroed_page(GFP_KERNEL);
	if (!handle->cur) {
		ret = -ENOMEM;
		goto err_close;
	}
	handle->cur_swap = alloc_swapdev_block(root_swap);
	if (!handle->cur_swap) {
		ret = -ENOSPC;
		goto err_rel;
	}
	handle->k = 0;
	handle->reqd_free_pages = reqd_free_pages();
	handle->first_sector = handle->cur_swap;
	return 0;
err_rel:
	release_swap_writer(handle);
err_close:
	swsusp_close(FMODE_WRITE);
	return ret;
}

static int swap_write_page(struct swap_map_handle *handle, void *buf,
		struct hib_bio_batch *hb)
{
	int error = 0;
	sector_t offset;

	if (!handle->cur)
		return -EINVAL;
	offset = alloc_swapdev_block(root_swap);
	error = write_page(buf, offset, hb);
	if (error)
		return error;
	handle->cur->entries[handle->k++] = offset;
	if (handle->k >= MAP_PAGE_ENTRIES) {
		offset = alloc_swapdev_block(root_swap);
		if (!offset)
			return -ENOSPC;
		handle->cur->next_swap = offset;
		error = write_page(handle->cur, handle->cur_swap, hb);
		if (error)
			goto out;
		clear_page(handle->cur);
		handle->cur_swap = offset;
		handle->k = 0;

		if (hb && low_free_pages() <= handle->reqd_free_pages) {
			error = hib_wait_io(hb);
			if (error)
				goto out;
			/*
			handle->reqd_free_pages = reqd_free_pages();
		}
	}
 out:
	return error;
}

static int flush_swap_writer(struct swap_map_handle *handle)
{
	if (handle->cur && handle->cur_swap)
		return write_page(handle->cur, handle->cur_swap, NULL);
	else
		return -EINVAL;
}

static int swap_writer_finish(struct swap_map_handle *handle,
		unsigned int flags, int error)
{
	if (!error) {
		pr_info("S");
		error = mark_swapfiles(handle, flags);
		pr_cont("|\n");
		flush_swap_writer(handle);
	}

	if (error)
		free_all_swap_pages(root_swap);
	release_swap_writer(handle);
	swsusp_close(FMODE_WRITE);

	return error;
}

#define LZO_HEADER	sizeof(size_t)

#define LZO_UNC_PAGES	32
#define LZO_UNC_SIZE	(LZO_UNC_PAGES * PAGE_SIZE)

#define LZO_CMP_PAGES	DIV_ROUND_UP(lzo1x_worst_compress(LZO_UNC_SIZE) + \
			             LZO_HEADER, PAGE_SIZE)
#define LZO_CMP_SIZE	(LZO_CMP_PAGES * PAGE_SIZE)

#define LZO_THREADS	3

#define LZO_MIN_RD_PAGES	1024
#define LZO_MAX_RD_PAGES	8192



static int save_image(struct swap_map_handle *handle,
                      struct snapshot_handle *snapshot,
                      unsigned int nr_to_write)
{
	unsigned int m;
	int ret;
	int nr_pages;
	int err2;
	struct hib_bio_batch hb;
	ktime_t start;
	ktime_t stop;

	hib_init_batch(&hb);

	pr_info("Saving image data pages (%u pages)...\n",
		nr_to_write);
	m = nr_to_write / 10;
	if (!m)
		m = 1;
	nr_pages = 0;
	start = ktime_get();
	while (1) {
		ret = snapshot_read_next(snapshot);
		if (ret <= 0)
			break;
		ret = swap_write_page(handle, data_of(*snapshot), &hb);
		if (ret)
			break;
		if (!(nr_pages % m))
			pr_info("Image saving progress: %3d%%\n",
				nr_pages / m * 10);
		nr_pages++;
	}
	err2 = hib_wait_io(&hb);
	hib_finish_batch(&hb);
	stop = ktime_get();
	if (!ret)
		ret = err2;
	if (!ret)
		pr_info("Image saving done\n");
	swsusp_show_speed(start, stop, nr_to_write, "Wrote");
	return ret;
}

struct crc_data {
	struct task_struct *thr;                  /* thread */
	atomic_t ready;                           /* ready to start flag */
	atomic_t stop;                            /* ready to stop flag */
	unsigned run_threads;                     /* nr current threads */
	wait_queue_head_t go;                     /* start crc update */
	wait_queue_head_t done;                   /* crc update done */
	u32 *crc32;                               /* points to handle's crc32 */
	size_t *unc_len[LZO_THREADS];             /* uncompressed lengths */
	unsigned char *unc[LZO_THREADS];          /* uncompressed data */
};

static int crc32_threadfn(void *data)
{
	struct crc_data *d = data;
	unsigned i;

	while (1) {
		wait_event(d->go, atomic_read(&d->ready) ||
		                  kthread_should_stop());
		if (kthread_should_stop()) {
			d->thr = NULL;
			atomic_set(&d->stop, 1);
			wake_up(&d->done);
			break;
		}
		atomic_set(&d->ready, 0);

		for (i = 0; i < d->run_threads; i++)
			*d->crc32 = crc32_le(*d->crc32,
			                     d->unc[i], *d->unc_len[i]);
		atomic_set(&d->stop, 1);
		wake_up(&d->done);
	}
	return 0;
}
struct cmp_data {
	struct task_struct *thr;                  /* thread */
	atomic_t ready;                           /* ready to start flag */
	atomic_t stop;                            /* ready to stop flag */
	int ret;                                  /* return code */
	wait_queue_head_t go;                     /* start compression */
	wait_queue_head_t done;                   /* compression done */
	size_t unc_len;                           /* uncompressed length */
	size_t cmp_len;                           /* compressed length */
	unsigned char unc[LZO_UNC_SIZE];          /* uncompressed buffer */
	unsigned char cmp[LZO_CMP_SIZE];          /* compressed buffer */
	unsigned char wrk[LZO1X_1_MEM_COMPRESS];  /* compression workspace */
};

static int lzo_compress_threadfn(void *data)
{
	struct cmp_data *d = data;

	while (1) {
		wait_event(d->go, atomic_read(&d->ready) ||
		                  kthread_should_stop());
		if (kthread_should_stop()) {
			d->thr = NULL;
			d->ret = -1;
			atomic_set(&d->stop, 1);
			wake_up(&d->done);
			break;
		}
		atomic_set(&d->ready, 0);

		d->ret = lzo1x_1_compress(d->unc, d->unc_len,
		                          d->cmp + LZO_HEADER, &d->cmp_len,
		                          d->wrk);
		atomic_set(&d->stop, 1);
		wake_up(&d->done);
	}
	return 0;
}

static int save_image_lzo(struct swap_map_handle *handle,
                          struct snapshot_handle *snapshot,
                          unsigned int nr_to_write)
{
	unsigned int m;
	int ret = 0;
	int nr_pages;
	int err2;
	struct hib_bio_batch hb;
	ktime_t start;
	ktime_t stop;
	size_t off;
	unsigned thr, run_threads, nr_threads;
	unsigned char *page = NULL;
	struct cmp_data *data = NULL;
	struct crc_data *crc = NULL;

	hib_init_batch(&hb);

	/*
	nr_threads = num_online_cpus() - 1;
	nr_threads = clamp_val(nr_threads, 1, LZO_THREADS);

	page = (void *)__get_free_page(GFP_NOIO | __GFP_HIGH);
	if (!page) {
		pr_err("Failed to allocate LZO page\n");
		ret = -ENOMEM;
		goto out_clean;
	}

	data = vzalloc(array_size(nr_threads, sizeof(*data)));
	if (!data) {
		pr_err("Failed to allocate LZO data\n");
		ret = -ENOMEM;
		goto out_clean;
	}

	crc = kzalloc(sizeof(*crc), GFP_KERNEL);
	if (!crc) {
		pr_err("Failed to allocate crc\n");
		ret = -ENOMEM;
		goto out_clean;
	}

	/*
	for (thr = 0; thr < nr_threads; thr++) {
		init_waitqueue_head(&data[thr].go);
		init_waitqueue_head(&data[thr].done);

		data[thr].thr = kthread_run(lzo_compress_threadfn,
		                            &data[thr],
		                            "image_compress/%u", thr);
		if (IS_ERR(data[thr].thr)) {
			data[thr].thr = NULL;
			pr_err("Cannot start compression threads\n");
			ret = -ENOMEM;
			goto out_clean;
		}
	}

	/*
	init_waitqueue_head(&crc->go);
	init_waitqueue_head(&crc->done);

	handle->crc32 = 0;
	crc->crc32 = &handle->crc32;
	for (thr = 0; thr < nr_threads; thr++) {
		crc->unc[thr] = data[thr].unc;
		crc->unc_len[thr] = &data[thr].unc_len;
	}

	crc->thr = kthread_run(crc32_threadfn, crc, "image_crc32");
	if (IS_ERR(crc->thr)) {
		crc->thr = NULL;
		pr_err("Cannot start CRC32 thread\n");
		ret = -ENOMEM;
		goto out_clean;
	}

	/*
	handle->reqd_free_pages = reqd_free_pages();

	pr_info("Using %u thread(s) for compression\n", nr_threads);
	pr_info("Compressing and saving image data (%u pages)...\n",
		nr_to_write);
	m = nr_to_write / 10;
	if (!m)
		m = 1;
	nr_pages = 0;
	start = ktime_get();
	for (;;) {
		for (thr = 0; thr < nr_threads; thr++) {
			for (off = 0; off < LZO_UNC_SIZE; off += PAGE_SIZE) {
				ret = snapshot_read_next(snapshot);
				if (ret < 0)
					goto out_finish;

				if (!ret)
					break;

				memcpy(data[thr].unc + off,
				       data_of(*snapshot), PAGE_SIZE);

				if (!(nr_pages % m))
					pr_info("Image saving progress: %3d%%\n",
						nr_pages / m * 10);
				nr_pages++;
			}
			if (!off)
				break;

			data[thr].unc_len = off;

			atomic_set(&data[thr].ready, 1);
			wake_up(&data[thr].go);
		}

		if (!thr)
			break;

		crc->run_threads = thr;
		atomic_set(&crc->ready, 1);
		wake_up(&crc->go);

		for (run_threads = thr, thr = 0; thr < run_threads; thr++) {
			wait_event(data[thr].done,
			           atomic_read(&data[thr].stop));
			atomic_set(&data[thr].stop, 0);

			ret = data[thr].ret;

			if (ret < 0) {
				pr_err("LZO compression failed\n");
				goto out_finish;
			}

			if (unlikely(!data[thr].cmp_len ||
			             data[thr].cmp_len >
			             lzo1x_worst_compress(data[thr].unc_len))) {
				pr_err("Invalid LZO compressed length\n");
				ret = -1;
				goto out_finish;
			}

			*(size_t *)data[thr].cmp = data[thr].cmp_len;

			/*
			for (off = 0;
			     off < LZO_HEADER + data[thr].cmp_len;
			     off += PAGE_SIZE) {
				memcpy(page, data[thr].cmp + off, PAGE_SIZE);

				ret = swap_write_page(handle, page, &hb);
				if (ret)
					goto out_finish;
			}
		}

		wait_event(crc->done, atomic_read(&crc->stop));
		atomic_set(&crc->stop, 0);
	}

out_finish:
	err2 = hib_wait_io(&hb);
	stop = ktime_get();
	if (!ret)
		ret = err2;
	if (!ret)
		pr_info("Image saving done\n");
	swsusp_show_speed(start, stop, nr_to_write, "Wrote");
out_clean:
	hib_finish_batch(&hb);
	if (crc) {
		if (crc->thr)
			kthread_stop(crc->thr);
		kfree(crc);
	}
	if (data) {
		for (thr = 0; thr < nr_threads; thr++)
			if (data[thr].thr)
				kthread_stop(data[thr].thr);
		vfree(data);
	}
	if (page) free_page((unsigned long)page);

	return ret;
}


static int enough_swap(unsigned int nr_pages)
{
	unsigned int free_swap = count_swap_pages(root_swap, 1);
	unsigned int required;

	pr_debug("Free swap pages: %u\n", free_swap);

	required = PAGES_FOR_IO + nr_pages;
	return free_swap > required;
}


int swsusp_write(unsigned int flags)
{
	struct swap_map_handle handle;
	struct snapshot_handle snapshot;
	struct swsusp_info *header;
	unsigned long pages;
	int error;

	pages = snapshot_get_image_size();
	error = get_swap_writer(&handle);
	if (error) {
		pr_err("Cannot get swap writer\n");
		return error;
	}
	if (flags & SF_NOCOMPRESS_MODE) {
		if (!enough_swap(pages)) {
			pr_err("Not enough free swap\n");
			error = -ENOSPC;
			goto out_finish;
		}
	}
	memset(&snapshot, 0, sizeof(struct snapshot_handle));
	error = snapshot_read_next(&snapshot);
	if (error < (int)PAGE_SIZE) {
		if (error >= 0)
			error = -EFAULT;

		goto out_finish;
	}
	header = (struct swsusp_info *)data_of(snapshot);
	error = swap_write_page(&handle, header, NULL);
	if (!error) {
		error = (flags & SF_NOCOMPRESS_MODE) ?
			save_image(&handle, &snapshot, pages - 1) :
			save_image_lzo(&handle, &snapshot, pages - 1);
	}
out_finish:
	error = swap_writer_finish(&handle, flags, error);
	return error;
}


static void release_swap_reader(struct swap_map_handle *handle)
{
	struct swap_map_page_list *tmp;

	while (handle->maps) {
		if (handle->maps->map)
			free_page((unsigned long)handle->maps->map);
		tmp = handle->maps;
		handle->maps = handle->maps->next;
		kfree(tmp);
	}
	handle->cur = NULL;
}

static int get_swap_reader(struct swap_map_handle *handle,
		unsigned int *flags_p)
{
	int error;
	struct swap_map_page_list *tmp, *last;
	sector_t offset;


	if (!swsusp_header->image) /* how can this happen? */
		return -EINVAL;

	handle->cur = NULL;
	last = handle->maps = NULL;
	offset = swsusp_header->image;
	while (offset) {
		tmp = kzalloc(sizeof(*handle->maps), GFP_KERNEL);
		if (!tmp) {
			release_swap_reader(handle);
			return -ENOMEM;
		}
		if (!handle->maps)
			handle->maps = tmp;
		if (last)
			last->next = tmp;
		last = tmp;

		tmp->map = (struct swap_map_page *)
			   __get_free_page(GFP_NOIO | __GFP_HIGH);
		if (!tmp->map) {
			release_swap_reader(handle);
			return -ENOMEM;
		}

		error = hib_submit_io(REQ_OP_READ, offset, tmp->map, NULL);
		if (error) {
			release_swap_reader(handle);
			return error;
		}
		offset = tmp->map->next_swap;
	}
	handle->k = 0;
	handle->cur = handle->maps->map;
	return 0;
}

static int swap_read_page(struct swap_map_handle *handle, void *buf,
		struct hib_bio_batch *hb)
{
	sector_t offset;
	int error;
	struct swap_map_page_list *tmp;

	if (!handle->cur)
		return -EINVAL;
	offset = handle->cur->entries[handle->k];
	if (!offset)
		return -EFAULT;
	error = hib_submit_io(REQ_OP_READ, offset, buf, hb);
	if (error)
		return error;
	if (++handle->k >= MAP_PAGE_ENTRIES) {
		handle->k = 0;
		free_page((unsigned long)handle->maps->map);
		tmp = handle->maps;
		handle->maps = handle->maps->next;
		kfree(tmp);
		if (!handle->maps)
			release_swap_reader(handle);
		else
			handle->cur = handle->maps->map;
	}
	return error;
}

static int swap_reader_finish(struct swap_map_handle *handle)
{
	release_swap_reader(handle);

	return 0;
}


static int load_image(struct swap_map_handle *handle,
                      struct snapshot_handle *snapshot,
                      unsigned int nr_to_read)
{
	unsigned int m;
	int ret = 0;
	ktime_t start;
	ktime_t stop;
	struct hib_bio_batch hb;
	int err2;
	unsigned nr_pages;

	hib_init_batch(&hb);

	clean_pages_on_read = true;
	pr_info("Loading image data pages (%u pages)...\n", nr_to_read);
	m = nr_to_read / 10;
	if (!m)
		m = 1;
	nr_pages = 0;
	start = ktime_get();
	for ( ; ; ) {
		ret = snapshot_write_next(snapshot);
		if (ret <= 0)
			break;
		ret = swap_read_page(handle, data_of(*snapshot), &hb);
		if (ret)
			break;
		if (snapshot->sync_read)
			ret = hib_wait_io(&hb);
		if (ret)
			break;
		if (!(nr_pages % m))
			pr_info("Image loading progress: %3d%%\n",
				nr_pages / m * 10);
		nr_pages++;
	}
	err2 = hib_wait_io(&hb);
	hib_finish_batch(&hb);
	stop = ktime_get();
	if (!ret)
		ret = err2;
	if (!ret) {
		pr_info("Image loading done\n");
		snapshot_write_finalize(snapshot);
		if (!snapshot_image_loaded(snapshot))
			ret = -ENODATA;
	}
	swsusp_show_speed(start, stop, nr_to_read, "Read");
	return ret;
}

struct dec_data {
	struct task_struct *thr;                  /* thread */
	atomic_t ready;                           /* ready to start flag */
	atomic_t stop;                            /* ready to stop flag */
	int ret;                                  /* return code */
	wait_queue_head_t go;                     /* start decompression */
	wait_queue_head_t done;                   /* decompression done */
	size_t unc_len;                           /* uncompressed length */
	size_t cmp_len;                           /* compressed length */
	unsigned char unc[LZO_UNC_SIZE];          /* uncompressed buffer */
	unsigned char cmp[LZO_CMP_SIZE];          /* compressed buffer */
};

static int lzo_decompress_threadfn(void *data)
{
	struct dec_data *d = data;

	while (1) {
		wait_event(d->go, atomic_read(&d->ready) ||
		                  kthread_should_stop());
		if (kthread_should_stop()) {
			d->thr = NULL;
			d->ret = -1;
			atomic_set(&d->stop, 1);
			wake_up(&d->done);
			break;
		}
		atomic_set(&d->ready, 0);

		d->unc_len = LZO_UNC_SIZE;
		d->ret = lzo1x_decompress_safe(d->cmp + LZO_HEADER, d->cmp_len,
		                               d->unc, &d->unc_len);
		if (clean_pages_on_decompress)
			flush_icache_range((unsigned long)d->unc,
					   (unsigned long)d->unc + d->unc_len);

		atomic_set(&d->stop, 1);
		wake_up(&d->done);
	}
	return 0;
}

static int load_image_lzo(struct swap_map_handle *handle,
                          struct snapshot_handle *snapshot,
                          unsigned int nr_to_read)
{
	unsigned int m;
	int ret = 0;
	int eof = 0;
	struct hib_bio_batch hb;
	ktime_t start;
	ktime_t stop;
	unsigned nr_pages;
	size_t off;
	unsigned i, thr, run_threads, nr_threads;
	unsigned ring = 0, pg = 0, ring_size = 0,
	         have = 0, want, need, asked = 0;
	unsigned long read_pages = 0;
	unsigned char **page = NULL;
	struct dec_data *data = NULL;
	struct crc_data *crc = NULL;

	hib_init_batch(&hb);

	/*
	nr_threads = num_online_cpus() - 1;
	nr_threads = clamp_val(nr_threads, 1, LZO_THREADS);

	page = vmalloc(array_size(LZO_MAX_RD_PAGES, sizeof(*page)));
	if (!page) {
		pr_err("Failed to allocate LZO page\n");
		ret = -ENOMEM;
		goto out_clean;
	}

	data = vzalloc(array_size(nr_threads, sizeof(*data)));
	if (!data) {
		pr_err("Failed to allocate LZO data\n");
		ret = -ENOMEM;
		goto out_clean;
	}

	crc = kzalloc(sizeof(*crc), GFP_KERNEL);
	if (!crc) {
		pr_err("Failed to allocate crc\n");
		ret = -ENOMEM;
		goto out_clean;
	}

	clean_pages_on_decompress = true;

	/*
	for (thr = 0; thr < nr_threads; thr++) {
		init_waitqueue_head(&data[thr].go);
		init_waitqueue_head(&data[thr].done);

		data[thr].thr = kthread_run(lzo_decompress_threadfn,
		                            &data[thr],
		                            "image_decompress/%u", thr);
		if (IS_ERR(data[thr].thr)) {
			data[thr].thr = NULL;
			pr_err("Cannot start decompression threads\n");
			ret = -ENOMEM;
			goto out_clean;
		}
	}

	/*
	init_waitqueue_head(&crc->go);
	init_waitqueue_head(&crc->done);

	handle->crc32 = 0;
	crc->crc32 = &handle->crc32;
	for (thr = 0; thr < nr_threads; thr++) {
		crc->unc[thr] = data[thr].unc;
		crc->unc_len[thr] = &data[thr].unc_len;
	}

	crc->thr = kthread_run(crc32_threadfn, crc, "image_crc32");
	if (IS_ERR(crc->thr)) {
		crc->thr = NULL;
		pr_err("Cannot start CRC32 thread\n");
		ret = -ENOMEM;
		goto out_clean;
	}

	/*
	if (low_free_pages() > snapshot_get_image_size())
		read_pages = (low_free_pages() - snapshot_get_image_size()) / 2;
	read_pages = clamp_val(read_pages, LZO_MIN_RD_PAGES, LZO_MAX_RD_PAGES);

	for (i = 0; i < read_pages; i++) {
		page[i] = (void *)__get_free_page(i < LZO_CMP_PAGES ?
						  GFP_NOIO | __GFP_HIGH :
						  GFP_NOIO | __GFP_NOWARN |
						  __GFP_NORETRY);

		if (!page[i]) {
			if (i < LZO_CMP_PAGES) {
				ring_size = i;
				pr_err("Failed to allocate LZO pages\n");
				ret = -ENOMEM;
				goto out_clean;
			} else {
				break;
			}
		}
	}
	want = ring_size = i;

	pr_info("Using %u thread(s) for decompression\n", nr_threads);
	pr_info("Loading and decompressing image data (%u pages)...\n",
		nr_to_read);
	m = nr_to_read / 10;
	if (!m)
		m = 1;
	nr_pages = 0;
	start = ktime_get();

	ret = snapshot_write_next(snapshot);
	if (ret <= 0)
		goto out_finish;

	for(;;) {
		for (i = 0; !eof && i < want; i++) {
			ret = swap_read_page(handle, page[ring], &hb);
			if (ret) {
				/*
				if (handle->cur &&
				    handle->cur->entries[handle->k]) {
					goto out_finish;
				} else {
					eof = 1;
					break;
				}
			}
			if (++ring >= ring_size)
				ring = 0;
		}
		asked += i;
		want -= i;

		/*
		if (!have) {
			if (!asked)
				break;

			ret = hib_wait_io(&hb);
			if (ret)
				goto out_finish;
			have += asked;
			asked = 0;
			if (eof)
				eof = 2;
		}

		if (crc->run_threads) {
			wait_event(crc->done, atomic_read(&crc->stop));
			atomic_set(&crc->stop, 0);
			crc->run_threads = 0;
		}

		for (thr = 0; have && thr < nr_threads; thr++) {
			data[thr].cmp_len = *(size_t *)page[pg];
			if (unlikely(!data[thr].cmp_len ||
			             data[thr].cmp_len >
			             lzo1x_worst_compress(LZO_UNC_SIZE))) {
				pr_err("Invalid LZO compressed length\n");
				ret = -1;
				goto out_finish;
			}

			need = DIV_ROUND_UP(data[thr].cmp_len + LZO_HEADER,
			                    PAGE_SIZE);
			if (need > have) {
				if (eof > 1) {
					ret = -1;
					goto out_finish;
				}
				break;
			}

			for (off = 0;
			     off < LZO_HEADER + data[thr].cmp_len;
			     off += PAGE_SIZE) {
				memcpy(data[thr].cmp + off,
				       page[pg], PAGE_SIZE);
				have--;
				want++;
				if (++pg >= ring_size)
					pg = 0;
			}

			atomic_set(&data[thr].ready, 1);
			wake_up(&data[thr].go);
		}

		/*
		if (have < LZO_CMP_PAGES && asked) {
			ret = hib_wait_io(&hb);
			if (ret)
				goto out_finish;
			have += asked;
			asked = 0;
			if (eof)
				eof = 2;
		}

		for (run_threads = thr, thr = 0; thr < run_threads; thr++) {
			wait_event(data[thr].done,
			           atomic_read(&data[thr].stop));
			atomic_set(&data[thr].stop, 0);

			ret = data[thr].ret;

			if (ret < 0) {
				pr_err("LZO decompression failed\n");
				goto out_finish;
			}

			if (unlikely(!data[thr].unc_len ||
			             data[thr].unc_len > LZO_UNC_SIZE ||
			             data[thr].unc_len & (PAGE_SIZE - 1))) {
				pr_err("Invalid LZO uncompressed length\n");
				ret = -1;
				goto out_finish;
			}

			for (off = 0;
			     off < data[thr].unc_len; off += PAGE_SIZE) {
				memcpy(data_of(*snapshot),
				       data[thr].unc + off, PAGE_SIZE);

				if (!(nr_pages % m))
					pr_info("Image loading progress: %3d%%\n",
						nr_pages / m * 10);
				nr_pages++;

				ret = snapshot_write_next(snapshot);
				if (ret <= 0) {
					crc->run_threads = thr + 1;
					atomic_set(&crc->ready, 1);
					wake_up(&crc->go);
					goto out_finish;
				}
			}
		}

		crc->run_threads = thr;
		atomic_set(&crc->ready, 1);
		wake_up(&crc->go);
	}

out_finish:
	if (crc->run_threads) {
		wait_event(crc->done, atomic_read(&crc->stop));
		atomic_set(&crc->stop, 0);
	}
	stop = ktime_get();
	if (!ret) {
		pr_info("Image loading done\n");
		snapshot_write_finalize(snapshot);
		if (!snapshot_image_loaded(snapshot))
			ret = -ENODATA;
		if (!ret) {
			if (swsusp_header->flags & SF_CRC32_MODE) {
				if(handle->crc32 != swsusp_header->crc32) {
					pr_err("Invalid image CRC32!\n");
					ret = -ENODATA;
				}
			}
		}
	}
	swsusp_show_speed(start, stop, nr_to_read, "Read");
out_clean:
	hib_finish_batch(&hb);
	for (i = 0; i < ring_size; i++)
		free_page((unsigned long)page[i]);
	if (crc) {
		if (crc->thr)
			kthread_stop(crc->thr);
		kfree(crc);
	}
	if (data) {
		for (thr = 0; thr < nr_threads; thr++)
			if (data[thr].thr)
				kthread_stop(data[thr].thr);
		vfree(data);
	}
	vfree(page);

	return ret;
}


int swsusp_read(unsigned int *flags_p)
{
	int error;
	struct swap_map_handle handle;
	struct snapshot_handle snapshot;
	struct swsusp_info *header;

	memset(&snapshot, 0, sizeof(struct snapshot_handle));
	error = snapshot_write_next(&snapshot);
	if (error < (int)PAGE_SIZE)
		return error < 0 ? error : -EFAULT;
	header = (struct swsusp_info *)data_of(snapshot);
	error = get_swap_reader(&handle, flags_p);
	if (error)
		goto end;
	if (!error)
		error = swap_read_page(&handle, header, NULL);
	if (!error) {
		error = (*flags_p & SF_NOCOMPRESS_MODE) ?
			load_image(&handle, &snapshot, header->pages - 1) :
			load_image_lzo(&handle, &snapshot, header->pages - 1);
	}
	swap_reader_finish(&handle);
end:
	if (!error)
		pr_debug("Image successfully loaded\n");
	else
		pr_debug("Error %d resuming\n", error);
	return error;
}


int swsusp_check(void)
{
	int error;
	void *holder;

	hib_resume_bdev = blkdev_get_by_dev(swsusp_resume_device,
					    FMODE_READ | FMODE_EXCL, &holder);
	if (!IS_ERR(hib_resume_bdev)) {
		set_blocksize(hib_resume_bdev, PAGE_SIZE);
		clear_page(swsusp_header);
		error = hib_submit_io(REQ_OP_READ, swsusp_resume_block,
					swsusp_header, NULL);
		if (error)
			goto put;

		if (!memcmp(HIBERNATE_SIG, swsusp_header->sig, 10)) {
			memcpy(swsusp_header->sig, swsusp_header->orig_sig, 10);
			/* Reset swap signature now */
			error = hib_submit_io(REQ_OP_WRITE | REQ_SYNC,
						swsusp_resume_block,
						swsusp_header, NULL);
		} else {
			error = -EINVAL;
		}
		if (!error && swsusp_header->flags & SF_HW_SIG &&
		    swsusp_header->hw_sig != swsusp_hardware_signature) {
			pr_info("Suspend image hardware signature mismatch (%08x now %08x); aborting resume.\n",
				swsusp_header->hw_sig, swsusp_hardware_signature);
			error = -EINVAL;
		}

put:
		if (error)
			blkdev_put(hib_resume_bdev, FMODE_READ | FMODE_EXCL);
		else
			pr_debug("Image signature found, resuming\n");
	} else {
		error = PTR_ERR(hib_resume_bdev);
	}

	if (error)
		pr_debug("Image not found (code %d)\n", error);

	return error;
}


void swsusp_close(fmode_t mode)
{
	if (IS_ERR(hib_resume_bdev)) {
		pr_debug("Image device not initialised\n");
		return;
	}

	blkdev_put(hib_resume_bdev, mode);
}


#ifdef CONFIG_SUSPEND
int swsusp_unmark(void)
{
	int error;

	hib_submit_io(REQ_OP_READ, swsusp_resume_block,
			swsusp_header, NULL);
	if (!memcmp(HIBERNATE_SIG,swsusp_header->sig, 10)) {
		memcpy(swsusp_header->sig,swsusp_header->orig_sig, 10);
		error = hib_submit_io(REQ_OP_WRITE | REQ_SYNC,
					swsusp_resume_block,
					swsusp_header, NULL);
	} else {
		pr_err("Cannot find swsusp signature!\n");
		error = -ENODEV;
	}

	/*
	free_all_swap_pages(root_swap);

	return error;
}
#endif

static int __init swsusp_header_init(void)
{
	swsusp_header = (struct swsusp_header*) __get_free_page(GFP_KERNEL);
	if (!swsusp_header)
		panic("Could not allocate memory for swsusp_header\n");
	return 0;
}

core_initcall(swsusp_header_init);
