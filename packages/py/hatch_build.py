"""tag staged release wheels that include the native CLI."""

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, object]) -> None:
        build_data["pure_python"] = False
        build_data["tag"] = self.config["tag"]
