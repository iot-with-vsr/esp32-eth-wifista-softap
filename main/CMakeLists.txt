file(GLOB_RECURSE cfiles "./src/*.c") 
file(GLOB_RECURSE cppfiles "./src/*.cpp") 
idf_component_register(SRCS "main.c" ${cfiles} ${cppfiles}
                       INCLUDE_DIRS "inc")


set(SPIFFS_DATA_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../data")
if(EXISTS ${SPIFFS_DATA_SRC_DIR}/frontend)
    spiffs_create_partition_image(www ${SPIFFS_DATA_SRC_DIR}/frontend FLASH_IN_PROJECT)
else()
    message(FATAL_ERROR "${SPIFFS_DATA_SRC_DIR} doesn't exit")
endif()
