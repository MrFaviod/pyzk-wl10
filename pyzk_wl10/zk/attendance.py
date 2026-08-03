# -*- coding: utf-8 -*-
from datetime import datetime

from zk import const


class Attendance(object):
    def __init__(self, user_id, timestamp, status, punch=0, uid=0, name='', badge=''):
        self.uid = uid
        self.user_id = user_id
        self.timestamp = timestamp
        self.status = status
        self.punch = punch
        self.name = name
        self.badge = badge

    @property
    def status_label(self):
        """Human-readable name for the numeric punch state.

        The status byte (offset 17 of the 22B WL10 record) is a numeric
        enum: 0=Check-In, 1=Check-Out, 2=Break-Out, 3=Break-In,
        4=Overtime-In, 5=Overtime-Out. Firmwares may remap these values
        depending on the function-key configuration, so unknown values
        fall back to 'Unknown' instead of guessing.
        """
        return const.WL10_PUNCH_STATES.get(self.status, 'Unknown')

    def __str__(self):
        return '<Attendance>: {} {} : {} ({}, {})'.format(self.badge, self.name, self.timestamp, self.status, self.punch)

    def __repr__(self):
        return '<Attendance>: {} {} : {} ({}, {})'.format(self.badge, self.name, self.timestamp, self.status, self.punch)