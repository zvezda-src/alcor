
#ifndef _UAPI_ASM_X86_AMD_HSMP_H_
#define _UAPI_ASM_X86_AMD_HSMP_H_

#include <linux/types.h>

#pragma pack(4)

#define HSMP_MAX_MSG_LEN 8

enum hsmp_message_ids {
	HSMP_TEST = 1,			/* 01h Increments input value by 1 */
	HSMP_GET_SMU_VER,		/* 02h SMU FW version */
	HSMP_GET_PROTO_VER,		/* 03h HSMP interface version */
	HSMP_GET_SOCKET_POWER,		/* 04h average package power consumption */
	HSMP_SET_SOCKET_POWER_LIMIT,	/* 05h Set the socket power limit */
	HSMP_GET_SOCKET_POWER_LIMIT,	/* 06h Get current socket power limit */
	HSMP_GET_SOCKET_POWER_LIMIT_MAX,/* 07h Get maximum socket power value */
	HSMP_SET_BOOST_LIMIT,		/* 08h Set a core maximum frequency limit */
	HSMP_SET_BOOST_LIMIT_SOCKET,	/* 09h Set socket maximum frequency level */
	HSMP_GET_BOOST_LIMIT,		/* 0Ah Get current frequency limit */
	HSMP_GET_PROC_HOT,		/* 0Bh Get PROCHOT status */
	HSMP_SET_XGMI_LINK_WIDTH,	/* 0Ch Set max and min width of xGMI Link */
	HSMP_SET_DF_PSTATE,		/* 0Dh Alter APEnable/Disable messages behavior */
	HSMP_SET_AUTO_DF_PSTATE,	/* 0Eh Enable DF P-State Performance Boost algorithm */
	HSMP_GET_FCLK_MCLK,		/* 0Fh Get FCLK and MEMCLK for current socket */
	HSMP_GET_CCLK_THROTTLE_LIMIT,	/* 10h Get CCLK frequency limit in socket */
	HSMP_GET_C0_PERCENT,		/* 11h Get average C0 residency in socket */
	HSMP_SET_NBIO_DPM_LEVEL,	/* 12h Set max/min LCLK DPM Level for a given NBIO */
	HSMP_GET_NBIO_DPM_LEVEL,	/* 13h Get LCLK DPM level min and max for a given NBIO */
	HSMP_GET_DDR_BANDWIDTH,		/* 14h Get theoretical maximum and current DDR Bandwidth */
	HSMP_GET_TEMP_MONITOR,		/* 15h Get socket temperature */
	HSMP_GET_DIMM_TEMP_RANGE,	/* 16h Get per-DIMM temperature range and refresh rate */
	HSMP_GET_DIMM_POWER,		/* 17h Get per-DIMM power consumption */
	HSMP_GET_DIMM_THERMAL,		/* 18h Get per-DIMM thermal sensors */
	HSMP_GET_SOCKET_FREQ_LIMIT,	/* 19h Get current active frequency per socket */
	HSMP_GET_CCLK_CORE_LIMIT,	/* 1Ah Get CCLK frequency limit per core */
	HSMP_GET_RAILS_SVI,		/* 1Bh Get SVI-based Telemetry for all rails */
	HSMP_GET_SOCKET_FMAX_FMIN,	/* 1Ch Get Fmax and Fmin per socket */
	HSMP_GET_IOLINK_BANDWITH,	/* 1Dh Get current bandwidth on IO Link */
	HSMP_GET_XGMI_BANDWITH,		/* 1Eh Get current bandwidth on xGMI Link */
	HSMP_SET_GMI3_WIDTH,		/* 1Fh Set max and min GMI3 Link width */
	HSMP_SET_PCI_RATE,		/* 20h Control link rate on PCIe devices */
	HSMP_SET_POWER_MODE,		/* 21h Select power efficiency profile policy */
	HSMP_SET_PSTATE_MAX_MIN,	/* 22h Set the max and min DF P-State  */
	HSMP_MSG_ID_MAX,
};

struct hsmp_message {
	__u32	msg_id;			/* Message ID */
	__u16	num_args;		/* Number of input argument words in message */
	__u16	response_sz;		/* Number of expected output/response words */
	__u32	args[HSMP_MAX_MSG_LEN];	/* argument/response buffer */
	__u16	sock_ind;		/* socket number */
};

enum hsmp_msg_type {
	HSMP_RSVD = -1,
	HSMP_SET  = 0,
	HSMP_GET  = 1,
};

struct hsmp_msg_desc {
	int num_args;
	int response_sz;
	enum hsmp_msg_type type;
};

static const struct hsmp_msg_desc hsmp_msg_desc_table[] = {
	/* RESERVED */
	{0, 0, HSMP_RSVD},

	/*
	{1, 1, HSMP_GET},

	/*
	{0, 1, HSMP_GET},

	/*
	{0, 1, HSMP_GET},

	/*
	{0, 1, HSMP_GET},

	/*
	{1, 0, HSMP_SET},

	/*
	{0, 1, HSMP_GET},

	/*
	{0, 1, HSMP_GET},

	/*
	{1, 0, HSMP_SET},

	/*
	{1, 0, HSMP_SET},

	/*
	{1, 1, HSMP_GET},

	/*
	{0, 1, HSMP_GET},

	/*
	{1, 0, HSMP_SET},

	/*
	{1, 0, HSMP_SET},

	/* HSMP_SET_AUTO_DF_PSTATE, num_args = 0, response_sz = 0 */
	{0, 0, HSMP_SET},

	/*
	{0, 2, HSMP_GET},

	/*
	{0, 1, HSMP_GET},

	/*
	{0, 1, HSMP_GET},

	/*
	{1, 0, HSMP_SET},

	/*
	{1, 1, HSMP_GET},

	/*
	{0, 1, HSMP_GET},

	/*
	{0, 1, HSMP_GET},

	/*
	{1, 1, HSMP_GET},

	/*
	{1, 1, HSMP_GET},

	/*
	{1, 1, HSMP_GET},

	/*
	{0, 1, HSMP_GET},

	/*
	{1, 1, HSMP_GET},

	/*
	{0, 1, HSMP_GET},

	/*
	{0, 1, HSMP_GET},

	/*
	{1, 1, HSMP_GET},

	/*
	{1, 1, HSMP_GET},

	/*
	{1, 0, HSMP_SET},

	/*
	{1, 1, HSMP_SET},

	/*
	{1, 0, HSMP_SET},

	/*
	{1, 0, HSMP_SET},
};

#pragma pack()

#define HSMP_BASE_IOCTL_NR	0xF8
#define HSMP_IOCTL_CMD		_IOWR(HSMP_BASE_IOCTL_NR, 0, struct hsmp_message)

#endif /*_ASM_X86_AMD_HSMP_H_*/
