#// Intel Proprietary
#//
#// Copyright 2021 Intel Corporation All Rights Reserved.
#//
#// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
#//
#// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
#// of merchantability, non-infringement, title, or fitness for a particular purpose.

include src_defs.mk
include compiler_defs.mk

.PHONY: default all clean

MSG := echo -e

ifndef RELEASE
TARGET = $(DEBUG_TARGET)
TARGET_DIR = $(DEBUG_DIR)
OBJS_DIR = $(DEBUG_DIR)/$(OBJ_DIR_NAME)
else
TARGET = $(RELEASE_TARGET)
TARGET_DIR = $(RELEASE_DIR)
OBJS_DIR = $(RELEASE_DIR)/$(OBJ_DIR_NAME)
endif

C_OBJECTS = $(foreach obj,$(__C_OBJECTS),$(OBJS_DIR)/$(obj))
ASM_OBJECTS = $(foreach obj,$(__ASM_OBJECTS),$(OBJS_DIR)/$(obj))
OBJECTS = $(C_OBJECTS) $(ASM_OBJECTS)
DEPS := $(OBJECTS:.o=.d)

CFLAGS += -D__FILENAME__=\"$(lastword $(subst /, ,$<))\"

CRYPTO_OBJECTS := $(CRYPTO_LIB_PATH)/$(CRYPTO_LIB_FILENAME)

default: $(TARGET) postBuildScripts
all: default

$(CRYPTO_OBJECTS): $(CRYPTO_LIB_SRC_DIR)
	cd $(CRYPTO_LIB_MAIN_DIR); \
	CC=$(CC_WITHOUT_CODE_COVERAGE) CXX=$(CXX_WITHOUT_CODE_COVERAGE) cmake CMakeLists.txt \
	-B_build -DARCH=intel64 -DMERGED_BLD:BOOL=off -DPLATFORM_LIST="y8" \
	-DIPPCP_CUSTOM_BUILD="IPPCP_AES_ON;IPPCP_CLMUL_ON;IPPCP_VAES_ON;IPPCP_VCLMUL_ON"; \
	cd _build; \
	make -j8 ippcp_s_y8

$(C_OBJECTS): $(OBJS_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(INCLUDE_PATH) $(CFLAGS) -c $< -o $@

$(ASM_OBJECTS): $(OBJS_DIR)/%.o: %.S
	@mkdir -p $(@D)
	$(CC) $(INCLUDE_PATH) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

ORIG_TARGET := $(TARGET_DIR)/libtdx_unstripped.so

$(TARGET): $(CRYPTO_OBJECTS) $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -L$(CRYPTO_LIB_PATH) $(CRYPTO_LIB) -o $@
	cp $(TARGET) $(ORIG_TARGET)

postBuildScripts: $(TARGET)
ifndef DO_NOT_STRIP
ifdef RELEASE
	strip -s $(RELEASE_DIR)/libtdx.so
endif #RELEASE
endif #DO_NOT_STRIP

	#The padding operation must be the last change made to the binary 
	$(MSG) "Padding Binary to page size granularity"
	python3 $(PAD_BINARY_PY) $<
	
	rm -f $(ORIG_TARGET)
	
clean:
	rm -rf $(DEBUG_DIR)/$(OBJ_DIR_NAME)
	rm -rf $(RELEASE_DIR)/$(OBJ_DIR_NAME)
	rm -f $(DEBUG_TARGET)
	rm -f $(RELEASE_TARGET)
	rm -f $(ORIG_TARGET)
	rm -rf $(ARCHITECTURE_REPOSITORY_CLONE_PATH)

cleanall:
	rm -rf $(CRYPTO_LIB_MAIN_DIR)/_build
	make clean

help:
	@echo "\nTDX Module Makefile - available build flag options (use with regular 'make' command):"
	@echo "\tRELEASE=1                  - builds a release flavor of the library."
	@echo "\tDBG_TRACE=1                - enables debug trace capabilities."
	@echo "\nAdditional make targets:"
	@echo "\tmake clean                 - cleans everything except crypto library."
	@echo "\tmake cleanall              - cleans everything including the crypto library."

-include $(DEPS) $(CPP_DEPS)
