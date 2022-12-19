import json

class CPE:
    """JSON dump class for CPEs

    :var deprecated: Indicates whether CPE has been deprecated
    :vartype deprecated: bool

    :var cpeName: CPE URI name
    :vartype name: str

    :var cpeNameId: CPE UUID
    :vartype cpeNameId: str

    :var lastModifiedDate: CPE modification date
    :vartype lastModifiedDate: 

    :var created: CPE creation date
    :vartype created: str

    :var titles: List of available titles for the CPE
    :vartype title: list

    :var deprecatedBy: If deprecated=true, one or more CPE that replace this one
    :vartype deprecatedby: list

    :var vulnerabilities: Optional vulnerabilities associated with this CPE. Must use 'cves = true' argument in searchCPE.
    :vartype vulnerabilities: list
    """

    def __init__(self, response):
        vars(self).update(response)

    def __repr__(self):
        return str(self.__dict__)

    def __len__(self):
        return len(vars(self))

    def __iter__(self):
        yield 5
        yield from list(self.__dict__.keys())


class CVE:
    """JSON dump class for CVEs
        For more information the values returned from a CVE, please visit https://nvd.nist.gov/developers/vulnerabilities
    
    :var id: CVE ID
    :vartype id: str

    :var sourceIdentifier: Contact who reported the vulnerability.
    :vartype sourceIdentifier: str

    :var published: CVE publication date. ISO 8601 date/time format.
    :vartype published: str

    :var lastModified: CVE modified date. ISO 8601 date/time format.
    :vartype lastModified: str

    :var vulnStatus: CVE modified status.
    :vartype vulnStatus: str

    :var exploitAdd: Optional, only exists if the CVE is listed in the Known Exploited Vulnerabilities (KEV) catalog.
    :vartype exploitAdd: str

    :var actionDue: Optional, only exists if the CVE is listed in the Known Exploited Vulnerabilities (KEV) catalog.
    :vartype actionDue: str

    :var requiredAction: Optional, only exists if the CVE is listed in the Known Exploited Vulnerabilities (KEV) catalog.
    :vartype requiredAction: str

    :var descriptions: CVE descriptions. Includes other languages.
    :vartype descriptions: list

    :var metrics: Class attribute containing scoring lists (cvssMetricV31 / V30 / V2).
    :vartype metrics: class

    :var weaknesses: Contains relevant CWE information.
    :vartype weaknesses: list

    :var configurations: List containing usually a single element of CPE information.
    :vartype configuration: list

    :var references: CVE reference links
    :vartype references: list

    :var cwe: Common Weakness Enumeration Specification (CWE)
    :vartype cwe: list

    :var url: Link to additional details on nvd.nist.gov for that CVE.
    :vartype url: str

    :var cpe: Common Platform Enumeration (CPE) assigned to the CVE.
    :vartype cpe: list

    :var metrics: CVSS metrics. Some CVEs may not have v2/v3 scores or none at all.
    :vartype metrics: dict

    :var v30score: List that contains V3.0 CVSS score (float 1 - 10) as index 0 and the version that score was taken from as index 1.
    :vartype v3score: list

    :var v2vector: Version two of the CVSS score represented as a vector string, a compressed textual representation of the values used to derive the score. Example: 'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'
    :vartype v2vector: str

    :var v3vector: Version three of the CVSS score represented as a vector string.
    :vartype v3vector: str

    :var v2severity: LOW, MEDIUM, HIGH (Critical is only available for v3).
    :vartype v2severity: str

    :var v3severity: LOW, MEDIUM, HIGH, CRITICAL.
    :vartype v3severity: str

    :var v2exploitability: Version 2 CVSS exploitability. Reflects the ease and technical means by which the vulnerability can be exploited.
    :vartype v2exploitability: float 

    :var v3exploitability: Version 3 CVSS exploitability. Reflects the ease and technical means by which the vulnerability can be exploited.
    :vartype v3exploitability: float 

    :var v2impactScore: Reflects the direct consequence of a successful exploit.
    :vartype v2impactScore: float

    :var v3impactScore: Reflects the direct consequence of a successful exploit.
    :vartype v3impactScore: float

    :var score: Contains the v3 CVSS score (v2 if v3 isn't available) [score, severity, version]. Where score is an int, severity is a string('LOW','MEDIUM','HIGH','CRITICAL'), and version is a string (V3 or V2).
    :vartype score: list
    """

    def __init__(self, response):
        vars(self).update(response)

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return str(self.__dict__)

    def __len__(self):
        return len(vars(self))

    def __iter__(self):
        yield 5
        yield from list(self.__dict__.keys())


    def getvars(self):
        try:
            self.cpe = [x.cpeMatch[0] for x in self.configurations[0].nodes]
        except AttributeError:
            pass
        
        try:
            self.cwe = [x.description[0] for x in self.weaknesses]
        except AttributeError:
            pass

        try:
            self.url = 'https://nvd.nist.gov/vuln/detail/' + self.id
        except:
            pass
        
        if hasattr(self.metrics, 'cvssMetricV31'):
            self.v31score = self.metrics.cvssMetricV31[0].cvssData.baseScore
            self.v31vector = self.metrics.cvssMetricV31[0].cvssData.vectorString
            self.v31severity = self.metrics.cvssMetricV31[0].cvssData.baseSeverity
            self.v31exploitability = self.metrics.cvssMetricV31[0].exploitabilityScore
            self.v31impactScore = self.metrics.cvssMetricV31[0].impactScore

        if hasattr(self.metrics, 'cvssMetricV30'):
            self.v30score = self.metrics.cvssMetricV30[0].cvssData.baseScore
            self.v30vector = self.metrics.cvssMetricV30[0].cvssData.vectorString
            self.v30severity = self.metrics.cvssMetricV30[0].cvssData.baseSeverity
            self.v30exploitability = self.metrics.cvssMetricV30[0].exploitabilityScore
            self.v30impactScore = self.metrics.cvssMetricV30[0].impactScore        

        if hasattr(self.metrics, 'cvssMetricV2'):
            self.v2score = self.metrics.cvssMetricV2[0].cvssData.baseScore
            self.v2vector = self.metrics.cvssMetricV2[0].cvssData.vectorString
            self.v2severity = self.metrics.cvssMetricV2[0].baseSeverity
            self.v2exploitability = self.metrics.cvssMetricV2[0].exploitabilityScore
            self.v2impactScore = self.metrics.cvssMetricV2[0].impactScore
        
        # Prefer the base score version to V3, if it isn't available use V2.
        # If no score is present, then set it to None.
        if hasattr(self.metrics, 'cvssMetricV31'):
            self.score = ['V31', self.v31score, self.v31severity]
        elif hasattr(self.metrics, 'cvssMetricV30'):
            self.score = ['V30', self.v30score, self.v30severity]
        elif hasattr(self.metrics, 'cvssMetricV2'):
            self.score = ['V2', self.v2score, self.v2severity]
        else:
            self.score = [None, None, None]

def __convert(product, CVEID):
    """Convert the JSON response to a referenceable object."""
    if product == 'cve':
        vuln = json.loads(json.dumps(CVEID), object_hook= CVE)
        vuln.getvars()
        return vuln
    else:
        cpeEntry = json.loads(json.dumps(CVEID), object_hook= CPE)
        return cpeEntry 