import { withTnl } from "../../dist/index.js";

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
