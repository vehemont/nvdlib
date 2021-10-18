import json

class CPE:
    """JSON Dump class for CPEs.

    getvars() -- Assigns commonly used variables to shorter attribute names. Ran automatically after retrieving data.


    Attributes:

    deprecated -- Indicates whether CPE has been deprecated.

    cpe23Uri -- The CPE name.

    lastModifiedDate -- CPE modification date

    titles -- Human-readable CPE titles.

    refs -- Reference links.

    deprecatedBy -- If deprecated=true, one or more CPE that replace this one.

    vulnerabilities -- Optional vulnerabilities associated with this CPE. Must use 'cves = true' argument in searchCPE.
    
    """
    def __init__(self, dict):
        vars(self).update(dict)

    def __repr__(self):
        return str(self.__dict__)

    def __len__(self):
        return len(vars(self))

    def __iter__(self):
        yield 5
        yield from list(self.__dict__.keys())

    def getvars(self):
        self.title = self.titles[0].title
        self.name = self.cpe23Uri


class CVE:
    """JSON Dump class for CVEs.
    
    getvars() -- Assigns commonly used variables to shorter attribute names. Ran automatically after retrieving data.

    Attributes:

    Static Attributes from JSON:

    cve -- CVE ID, description, reference links, CWE.

    configurations -- CPE applicability statements and optional CPE names.

    impact -- CVSS severity scores

    publishedDate -- CVE publication date

    lastModifiedDate -- CVE modified date.


    Custom attributes:

    id -- CVE ID number.

    cwe -- Common Weakness Enumeration Specification (CWE)

    url -- Link to additional details on nvd.nist.gov for that CVE.

    v3score -- List that contains V3 or V2 CVSS score (float 1 - 10) as index 0 and the version that score was taken from as index 1.

    v2/v3vector -- A CVSS score is also represented as a vector string, a compressed textual representation of the values used to derive the score.

    v2/v3severity -- LOW, MEDIUM, HIGH, or CRITICAL (Critical is only available for v3)

    v2/v3exploitability -- Float 1 - 10.

    v2/v3impactScore -- Float 1 - 10.

    """

    def __init__(self, dict):
        vars(self).update(dict)

    def __repr__(self):
        return str(self.__dict__)

    def __len__(self):
        return len(vars(self))

    def __iter__(self):
        yield 5
        yield from list(self.__dict__.keys())

    def getvars(self):
        
        self.id = self.cve.CVE_data_meta.ID
        self.cwe = self.cve.problemtype.problemtype_data
        self.url = 'https://nvd.nist.gov/vuln/detail/' + self.id

        if hasattr(self.impact, 'baseMetricV3'):
            self.v3score = self.impact.baseMetricV3.cvssV3.baseScore
            self.v3vector = self.impact.baseMetricV3.cvssV3.vectorString
            self.v3severity = self.impact.baseMetricV3.cvssV3.baseSeverity
            self.v3exploitability = self.impact.baseMetricV3.exploitabilityScore
            self.v3impactScore = self.impact.baseMetricV3.impactScore

        if hasattr(self.impact, 'baseMetricV2'):
            self.v2score = self.impact.baseMetricV2.cvssV2.baseScore
            self.v2vector = self.impact.baseMetricV2.cvssV2.vectorString
            self.v2severity = self.impact.baseMetricV2.severity
            self.v2exploitability = self.impact.baseMetricV2.exploitabilityScore
            self.v2impactScore = self.impact.baseMetricV2.impactScore
        
        if hasattr(self.impact, 'baseMetricV3'):
            self.score = [self.impact.baseMetricV3.cvssV3.baseScore, 'V3']
        elif hasattr(self.impact, 'baseMetricV2'):
            self.score = [self.impact.baseMetricV2.cvssV2.baseScore, 'V2']

def __convert(product, CVEID):
    """Convert the JSON response to a referenceable object."""
    if product == 'cve':
        vuln = json.loads(json.dumps(CVEID), object_hook= CVE)
        vuln.getvars()
        return vuln
    else:
        cpeEntry = json.loads(json.dumps(CVEID), object_hook= CPE)
        return cpeEntry 