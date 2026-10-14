package localpublisher

import (
	"context"
	"fmt"
	"os/exec"
)

func activateService(ctx context.Context) error {
	if err := installServiceExecutable(); err != nil {
		return err
	}
	const name = "tnl-publisher.service"
	unit := fmt.Sprintf(`[Unit]
Description=tnl publisher service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=%s --no-telemetry publisher service serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, serviceExecutable())
	if err := writeServiceConfig("/etc/systemd/system/"+name, []byte(unit)); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", name}} {
		if err := exec.CommandContext(ctx, "systemctl", args...).Run(); err != nil {
			return err
		}
	}
	return nil
}
