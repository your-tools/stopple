CREATE TABLE vulnerability (
    cve STRING NOT NULL,
    description STRING NOT NULL,
    severity STRING,
    FOREIGN KEY (cve) REFERENCES cve(id)
);

CREATE TABLE affected_versions (
    start VARCHAR(100) NOT NULL,
    end VARCHAR(100) NOT NULL,
    vulnerability VARCHAR(100) NOT NULL,
    FOREIGN KEY (vulnerability) REFERENCES vulnerability(id)
);
