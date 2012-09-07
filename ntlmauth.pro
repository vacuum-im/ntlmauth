include(qmake/debug.inc)
include(qmake/config.inc)

#Project configuration
TARGET              = ntlmauth
QT                  = core gui xml network
include(ntlmauth.pri)

#Plugin specific libs
LIBS               += -lsecur32

#Default progect configuration
include(qmake/plugin.inc)

#Translation
TRANS_SOURCE_ROOT   = .
include(translations/languages.inc)
