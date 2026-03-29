BUILD_DIR = build
CMAKE_FLAGS = -G Ninja -DCMAKE_CXX_COMPILER_LAUNCHER=ccache -DCMAKE_C_COMPILER_LAUNCHER=ccache

.PHONY: build clean run debug test

build:
	@mkdir -p $(BUILD_DIR)
	@if [ ! -f $(BUILD_DIR)/build.ninja ]; then \
		cd $(BUILD_DIR) && cmake $(CMAKE_FLAGS) ..; \
	fi
	@cmake --build $(BUILD_DIR)
	@ln -sf "$(BUILD_DIR)/compile_commands.json" .

clean:
	@rm -rf $(BUILD_DIR)
	@echo "Build directory cleaned." 

run:
	@sudo $(BUILD_DIR)/TyrSecure

debug:
	@sudo cat /sys/kernel/tracing/trace_pipe

test:
	@cd $(BUILD_DIR) && ctest --output-on-failure