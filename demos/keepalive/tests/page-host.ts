import { HOST_PARENT, type Host } from "../src/peers/host.ts";

export const pageHost: Host = {
  origin: `https://p-${"a".repeat(26)}.${HOST_PARENT}`,
  publisherID: `pub_${"a".repeat(22)}`,
  runID: `srun_${"a".repeat(22)}`,
  runNumber: "1",
};
