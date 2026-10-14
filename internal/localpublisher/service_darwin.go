package localpublisher

import (
	"context"
	"fmt"
	"os/exec"
)

const serviceLabel = "dev.tnl.pub"

func activateService(ctx context.Context) error {
	if err := installServiceExecutable(); err != nil {
		return err
	}
	const path = "/Library/LaunchDaemons/dev.tnl.pub.plist"
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>dev.tnl.pub</string>
<key>ProgramArguments</key><array><string>%s</string><string>--no-telemetry</string><string>publisher</string><string>service</string><string>serve</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>`, serviceExecutable())
	if err := writeServiceConfig(path, []byte(plist)); err != nil {
		return err
	}
	if err := exec.CommandContext(ctx, "launchctl", "print", "system/"+serviceLabel).Run(); err == nil {
		return nil
	}
	return exec.CommandContext(ctx, "launchctl", "bootstrap", "system", path).Run()
}
