from sqlalchemy.dialects.postgresql import JSON
from recon import db


class Project(db.Model):
    id = db.Column(db.String(120), primary_key=True)
    domain = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(120), nullable=False)
    subdomains = db.Column(db.Integer(), nullable=False)
    subdomains_alive = db.Column(db.Integer(),nullable=False)
    scan_start = db.Column(db.Integer(),nullable=False)
    scan_complete = db.Column(db.Integer(), nullable=False)
    ips = db.Column(db.Integer(), nullable=False)
    status = db.Column(db.Boolean(),nullable=False)
    dir_scans = db.relationship('DirScans', backref='project', lazy=True)
    nuclei_scans = db.relationship('Nuclei',backref='project', lazy=True)
    summary_string = db.Column(db.String(2000), default='', nullable=True)


    def __init__(self, id, domain, description, subdomains, subdomains_alive, scan_start, scan_complete, ips, status, summary_string):
        self.id = id
        self.domain = domain
        self.description = description
        self.subdomains = subdomains
        self.subdomains_alive= subdomains_alive
        self.scan_start = scan_start
        self.ips = ips
        self.scan_complete = scan_complete
        self.status = status
        self.summary_string = summary_string

    def __repr__(self):
        return '<Project %r>' % self.id


class DirScans(db.Model):
    id = db.Column(db.String(120),primary_key=True)
    scanner = db.Column(db.String(50),nullable=True)
    scan_init = db.Column(db.Integer(), nullable=True)
    scan_end = db.Column(db.Integer(), nullable=True)
    parent_id = db.Column(db.String(120),db.ForeignKey('project.id'),nullable=False)
    status =  db.Column(db.Boolean(),nullable=False)

    def __init__(self, id, scanner, scan_init, scan_end, parent_id,status):
        self.id = id
        self.scanner = scanner
        self.scan_init = scan_init
        self.scan_end = scan_end
        self.parent_id = parent_id
        self.status= status

    def __repr__(self):
        return '<DirScans %r>' % self.id



class Nuclei(db.Model):
    id = db.Column(db.String(120),primary_key=True)
    scanner = db.Column(db.String(50),nullable=True)
    scan_init = db.Column(db.Integer(), nullable=True)
    scan_end = db.Column(db.Integer(), nullable=True)
    parent_id = db.Column(db.String(120),db.ForeignKey('project.id'),nullable=False)
    status =  db.Column(db.Boolean(),nullable=False)

    def __init__(self,id, scanner, scan_init, scan_end, parent_id,status):
        self.id = id
        self.scanner = scanner
        self.scan_init = scan_init
        self.scan_end = scan_end
        self.parent_id = parent_id
        self.status= status


    def __repr__(self):
        return '<Nuclei %r>' % self.id



class Config(db.Model):
    id = db.Column(db.String(120),primary_key=True)
    config_json = db.Column(db.String(1000),nullable=True)
    state = db.Column(db.Boolean(), nullable=True)


    def __init__(self, id, config_json, state):
        self.id = id
        self.config_json = config_json
        self.state = state

    def __repr__(self):
        return '<Config %r>' % self.id


