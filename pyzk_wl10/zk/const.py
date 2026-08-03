# -*- coding: utf-8 -*-

USHRT_MAX = 65535

CMD_DB_RRQ          = 7
CMD_USER_WRQ        = 8
CMD_USERTEMP_RRQ    = 9
CMD_USERTEMP_WRQ    = 10
CMD_OPTIONS_RRQ     = 11
CMD_OPTIONS_WRQ     = 12
CMD_ATTLOG_RRQ      = 13
CMD_CLEAR_DATA      = 14
CMD_CLEAR_ATTLOG    = 15
CMD_DELETE_USER     = 18
CMD_DELETE_USERTEMP = 19
CMD_CLEAR_ADMIN     = 20
CMD_USERGRP_RRQ     = 21
CMD_USERGRP_WRQ     = 22
CMD_USERTZ_RRQ      = 23
CMD_USERTZ_WRQ      = 24
CMD_GRPTZ_RRQ       = 25
CMD_GRPTZ_WRQ       = 26
CMD_TZ_RRQ          = 27
CMD_TZ_WRQ          = 28
CMD_ULG_RRQ         = 29
CMD_ULG_WRQ         = 30
CMD_UNLOCK          = 31
CMD_CLEAR_ACC       = 32
CMD_CLEAR_OPLOG     = 33
CMD_OPLOG_RRQ       = 34
CMD_GET_FREE_SIZES  = 50
CMD_ENABLE_CLOCK    = 57
CMD_STARTVERIFY     = 60
CMD_STARTENROLL     = 61
CMD_CANCELCAPTURE   = 62
CMD_STATE_RRQ       = 64
CMD_WRITE_LCD       = 66
CMD_CLEAR_LCD       = 67
CMD_GET_PINWIDTH    = 69
CMD_SMS_WRQ         = 70
CMD_SMS_RRQ         = 71
CMD_DELETE_SMS      = 72
CMD_UDATA_WRQ       = 73
CMD_DELETE_UDATA    = 74
CMD_DOORSTATE_RRQ   = 75
CMD_WRITE_MIFARE    = 76
CMD_EMPTY_MIFARE    = 78

CMD_GET_TIME        = 201
CMD_SET_TIME        = 202
CMD_REG_EVENT       = 500

CMD_CONNECT         = 1000
CMD_EXIT            = 1001
CMD_ENABLEDEVICE    = 1002
CMD_DISABLEDEVICE   = 1003
CMD_RESTART         = 1004
CMD_POWEROFF        = 1005
CMD_SLEEP           = 1006
CMD_RESUME          = 1007
CMD_CAPTUREFINGER   = 1009
CMD_TEST_TEMP       = 1011
CMD_CAPTUREIMAGE    = 1012
CMD_REFRESHDATA     = 1013
CMD_REFRESHOPTION   = 1014
CMD_TESTVOICE       = 1017
CMD_GET_VERSION     = 1100
CMD_CHANGE_SPEED    = 1101
CMD_AUTH            = 1102
CMD_PREPARE_DATA    = 1500
CMD_DATA            = 1501
CMD_FREE_DATA       = 1502
CMD_DATA_WRRQ       = 1503

CMD_ACK_OK          = 2000
CMD_ACK_ERROR       = 2001
CMD_ACK_DATA        = 2002
CMD_ACK_RETRY       = 2003
CMD_ACK_REPEAT      = 2004
CMD_ACK_UNAUTH      = 2005

CMD_ACK_UNKNOWN     = 0xffff
CMD_ACK_ERROR_CMD   = 0xfffd
CMD_ACK_ERROR_INIT  = 0xfffc
CMD_ACK_ERROR_DATA  = 0xfffb

EF_ATTLOG           = 1
EF_FINGER           = (1<<1)
EF_ENROLLUSER       = (1<<2)
EF_ENROLLFINGER     = (1<<3)
EF_BUTTON           = (1<<4)
EF_UNLOCK           = (1<<5)
EF_VERIFY           = (1<<7)
EF_FPFTR            = (1<<8)
EF_ALARM            = (1<<9)

USER_DEFAULT        = 0
USER_ENROLLER       = 2
USER_MANAGER        = 6
USER_ADMIN          = 14

FCT_ATTLOG          = 1
FCT_WORKCODE        = 8
FCT_FINGERTMP       = 2
FCT_OPLOG           = 4
FCT_USER            = 5
FCT_SMS             = 6
FCT_UDATA           = 7

MACHINE_PREPARE_DATA_1 = 20560
MACHINE_PREPARE_DATA_2 = 32130

WL10_USER_RECORD_SIZE = 72
WL10_ATT_RECORD_SIZE = 22

# Attendance record status byte (WL10 22B layout, offset 17):
# numeric punch state -- firmware may remap these depending on the
# function-key configuration, so treat as best-effort labels.
WL10_PUNCH_STATES = {
    0: 'Check-In',        # entrada
    1: 'Check-Out',       # salida
    2: 'Break-Out',       # salida a pausa
    3: 'Break-In',        # vuelta de pausa
    4: 'Overtime-In',     # entrada extra
    5: 'Overtime-Out',    # salida extra
}

# User record verify-mode byte (WL10 72B layout, offset 39):
# controls how the terminal authenticates the user at the reader and
# at the admin MENU. Real admin records on AK3750WIFI_TFT Ver 6.60
# store 0x01 here; the fork previously wrote 0x00 (pad) which left
# admins unable to authenticate at the menu.
WL10_VERIFY_MODES = {
    0: 'Password',      # teclear contraseña numérica
    1: 'Fingerprint',   # huella dactilar
    2: 'Card',          # tarjeta RF
}
WL10_VERIFY_DEFAULT = 1  # Fingerprint -- matches real admin records
