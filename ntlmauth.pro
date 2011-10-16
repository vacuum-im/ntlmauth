#Plugin file name
TARGET              = ntlmauth
include(config.inc)

#Project Configuration
TEMPLATE            = lib
CONFIG             += plugin
QT                  = core gui xml network
LIBS               += -l$${TARGET_UTILS}
LIBS               += -L$${VACUUM_LIB_PATH}
DEPENDPATH         += $${VACUUM_SRC_PATH}
INCLUDEPATH        += $${VACUUM_SRC_PATH}

#Plugin specific libs
LIBS               += -lsecur32

#Install
include(install.inc)

#Translation
include(translations.inc)

include(ntlmauth.pri)
