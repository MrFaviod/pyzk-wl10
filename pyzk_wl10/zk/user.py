from struct import pack


class User:
    encoding = 'UTF-8'

    def __init__(self, uid, name, privilege, password='', group_id='', user_id='', card=0, badge=''):  # noqa: PLR0913, PLR0917 — public dataclass API, signature is the interface
        self.uid = uid
        self.name = '{}'.format(name)
        self.privilege = privilege
        self.password = str(password)
        self.group_id = str(group_id)
        self.user_id = user_id
        self.card = int(card)
        self.badge = str(badge)

    @staticmethod
    def json_unpack(json):
        return User(
            uid=json['uid'],
            name=json['name'],
            privilege=json['privilege'],
            password=json['password'],
            group_id=json['group_id'],
            user_id=json['user_id'],
            card=json['card'],
            badge=json.get('badge', '')
        )

    def repack29(self):
        return pack("<BHB5s8sIxBhI", 2, self.uid, self.privilege, self.password.encode(User.encoding, errors='ignore'), self.name.encode(User.encoding, errors='ignore'), self.card, int(self.group_id) if self.group_id else 0, 0, int(self.user_id))

    def repack73(self):
        return pack("<BHB8s24sIB7sx24s", 2, self.uid, self.privilege,self.password.encode(User.encoding, errors='ignore'), self.name.encode(User.encoding, errors='ignore'), self.card, 1, str(self.group_id).encode(User.encoding, errors='ignore'), str(self.user_id).encode(User.encoding, errors='ignore'))

    def __str__(self):
        return '<User>: [uid:{}, name:{} user_id:{}]'.format(self.uid, self.name, self.user_id)

    def __repr__(self):
        return '<User>: [uid:{}, name:{} user_id:{}]'.format(self.uid, self.name, self.user_id)
