import { withTnl } from "@tnldotdev/tnl/next";

export default withTnl({
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [{ key: "X-Tnl-Fixture", value: "next" }],
      },
    ];
  },
});
