CREATE TABLE package (
    name STRING PRIMARY KEY NOT NULL
);

CREATE TABLE vulnerability (
    cve STRING NOT NULL,
    package STRING NOT NULL,
    FOREIGN KEY (cve) REFERENCES cve(id),
    FOREIGN KEY (package) REFERENCES package(name)
);
