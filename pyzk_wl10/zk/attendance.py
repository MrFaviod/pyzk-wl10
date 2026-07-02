# -*- coding: utf-8 -*-
from datetime import datetime


class Attendance(object):
    def __init__(self, user_id, timestamp, status, punch=0, uid=0, name='', badge=''):
        self.uid = uid
        self.user_id = user_id
        self.timestamp = timestamp
        self.status = status
        self.punch = punch
        self.name = name
        self.badge = badge

    def __str__(self):
        return '<Attendance>: {} {} : {} ({}, {})'.format(self.badge, self.name, self.timestamp, self.status, self.punch)

    def __repr__(self):
        return '<Attendance>: {} {} : {} ({}, {})'.format(self.badge, self.name, self.timestamp, self.status, self.punch)