package main

import (
	"os"
	"runtime-detector/internal/detectorapp"
)

func main() { detectorapp.Run(os.Args[1:]) }
