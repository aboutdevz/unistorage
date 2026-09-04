//go:build !windows

package main

import "syscall"

func configureDetachedProcess(attr *syscall.SysProcAttr) {
	attr.Setsid = true
}
