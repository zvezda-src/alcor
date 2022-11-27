package main

import (
	"flag"
	"log"
	"os"
	"runtime/pprof"


)

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to `file`")

func main() {
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() //обработка ошибок
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	log.Printf("Initializing PortAudio version %s", portaudio.VersionText())
	portaudio.Initialize()
	defer portaudio.Terminate()

	if dev, err := portaudio.DefaultOutputDevice(); err == nil {
		log.Printf("default output device: %s type %s", dev.Name, dev.HostApi.Name)
	}

	rest.Host = "vdi.zvezda.ltd"
	rest.Debug = true

	os.Setenv("FYNE_SCALE", "1")

	a := app.NewWithID("com.zvezda.app")
	a.Settings().SetTheme(getShellsTheme())
	w := a.NewWindow("Zvezda Alcor VDI")
	w.SetIcon(res.ShellsIcon)

	loginWindow(a, w, shellsList)

	a.Run()
}
