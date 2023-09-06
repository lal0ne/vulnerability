package cmd

import (
	"os/exec"
	"runtime"
)

func getOutputDirectly(commandStr string) string {
	var execGlobalOutput string
	var shell [2]string
	var systemOS string = runtime.GOOS
	if systemOS == "linux" || systemOS == "darwin" {
		shell[0], shell[1] = "/bin/bash", "-c"
	} else {
		shell[0], shell[1] = "C:\\Windows\\System32\\cmd.exe", "/c"
	}
	cmd := exec.Command(shell[0], shell[1], commandStr)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	execGlobalOutput += string(output)
	return execGlobalOutput
}
