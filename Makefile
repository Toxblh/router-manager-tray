APP_DIR=router-tray
TAURI_DIR=$(APP_DIR)/src-tauri

.PHONY: build-linux build-windows build-macos build-all clean

build-linux:
	cd $(APP_DIR) && cargo tauri build

build-windows:
	@echo "Windows cross-build from Linux requires mingw + tauri cross setup."
	@echo "Example target: x86_64-pc-windows-gnu"
	cd $(APP_DIR) && cargo tauri build --target x86_64-pc-windows-gnu

build-macos:
	@echo "macOS cross-build from Linux requires osxcross and SDKs."
	@echo "Example target: aarch64-apple-darwin or x86_64-apple-darwin"
	cd $(APP_DIR) && cargo tauri build --target aarch64-apple-darwin

build-all: build-linux build-windows build-macos

clean:
	cd $(APP_DIR) && cargo clean
