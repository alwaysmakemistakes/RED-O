package main

import (
	"os"
	"runtime-detector/internal/webapp"
)

func main() { webapp.Run(os.Args[1:]) }
