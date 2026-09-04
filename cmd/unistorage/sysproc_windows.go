//go:build windows

package main

import "syscall"

func configureDetachedProcess(attr *syscall.SysProcAttr) {
	// 0x00000200 = CREATE_NEW_PROCESS_GROUP, 0x00000008 = DETACHED_PROCESS
	attr.CreationFlags = 0x00000200 | 0x00000008
}
