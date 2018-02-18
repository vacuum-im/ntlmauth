cmake_minimum_required(VERSION 2.8)

project(ntlmauth-plugin)
set(PLUGIN_NAME "ntlmauth")

find_package(Qt5Core REQUIRED)
find_package(Qt5Gui REQUIRED)
find_package(Qt5Network REQUIRED)
find_package(Qt5Widgets REQUIRED)
find_package(Qt5Xml REQUIRED)

list(APPEND QT_LIBRARIES Qt5::Core Qt5::Gui Qt5::Network Qt5::Widgets Qt5::Xml)

list(APPEND ADD_LIBS secur32 )

if(MSVC)
	add_definitions(-DUNICODE -D_UNICODE)
endif()

set(SOURCES ntlmauthfeaturefactory.cpp ntlmauthfeature.cpp)
set(HEADERS ntlmauthfeaturefactory.h ntlmauthfeature.h)
set(MOC_HEADERS ntlmauthfeaturefactory.h ntlmauthfeature.h)

include_directories("${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}")

include("${CMAKE_SOURCE_DIR}/cmake/config.cmake")
include("${CMAKE_SOURCE_DIR}/translations/languages.cmake")
include("${CMAKE_SOURCE_DIR}/cmake/plugin.cmake")

#install(DIRECTORY "resources/menuicons"
#	DESTINATION "${INSTALL_RESOURCES}")
