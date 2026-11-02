//go:build !linux

package main

import "io"

type initEnv struct{}

var processInitEnv = initEnv{}

func initSecrets(args []string, stdout, stderr io.Writer, env initEnv) int { return 0 }
