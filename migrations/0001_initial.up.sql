CREATE TABLE cve (
    id VARCHAR(100) PRIMARY KEY NOT NULL,
    raw_json STRING NOT NULL
);

CREATE TABLE meta (
    name STRING PRIMARY KEY NOT NULL,
    value STRING NOT NULL
);

CREATE TABLE package (
    id STRING PRIMARY KEY NOT NULL
);

CREATE TABLE vulnerability (
    cve STRING NOT NULL,
    package STRING NOT NULL,
    FOREIGN KEY (cve) REFERENCES cve(id),
    FOREIGN KEY (package) REFERENCES package(id)
);
