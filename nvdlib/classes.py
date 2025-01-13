import json
from typing import Any, Union, Literal


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


class MatchString:
    """JSON dump class for CPE match strings

    :var matchCriteriaId: UUID match criteria
    :vartype matchCriteriaId: str

    :var criteria: CPE name
    :vartype criteria: str

    :var lastModifiedDate: Match string modification date
    :vartype lastModifiedDate: str

    :var cpeLastModified: CPE modification date
    :vartype cpeLastModified: str 

    :var created: CPE creation date
    :vartype created: str

    :var status: CPE active status
    :vartype status: str
    
    :var matches: CPE Names and IDs within the CPE Dictionary that matches the CPE Match Criteria
    :vartype matches: list
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

    :var v31score: Integer that contains V3.1 CVSS score (float 1 - 10). Optional, some CVEs may not contain version 3.1 CVSS scoring.
    :vartype v31score: int
    
    :var v30score: Integer that contains V3.0 CVSS score (float 1 - 10) Optional, some CVEs may not contain version 3.0 CVSS scoring.
    :vartype v30score: int
    
    :var v2score: Integer that contains V2 CVSS score (float 1 - 10) Optional, some CVEs may not contain version 2 CVSS scoring.
    :vartype v2score: int

    :var v31vector: Version 3.1 of the CVSS score represented as a vector string. Optional, some CVEs may not contain version 3.1 CVSS scoring.
    :vartype v31vector: str

    :var v30vector: Version 3.0 of the CVSS score represented as a vector string. Optional, some CVEs may not contain version 3.0 CVSS scoring.
    :vartype v30vector: str

    :var v2vector: Version 2 of the CVSS score represented as a vector string, a compressed textual representation of the values used to derive the score. Example: 'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'. Optional, some CVEs may not contain version 2 CVSS scoring.
    :vartype v2vector: str

    :var v31severity: LOW, MEDIUM, HIGH, CRITICAL. Optional, some CVEs may not contain version 3.1 CVSS scoring.
    :vartype v31severity: str

    :var v30severity: LOW, MEDIUM, HIGH, CRITICAL. Optional, some CVEs may not contain version 3.0 CVSS scoring.
    :vartype v30severity: str

    :var v2severity: LOW, MEDIUM, HIGH (Critical is only available for v3). Optional, some CVEs may not contain version 2 CVSS scoring.
    :vartype v2severity: str

    :var v31exploitability: Version 3.1 CVSS exploitability. Reflects the ease and technical means by which the vulnerability can be exploited. Optional, some CVEs may not contain version 3.1 CVSS scoring.
    :vartype v31exploitability: float 

    :var v30exploitability: Version 3.0 CVSS exploitability. Reflects the ease and technical means by which the vulnerability can be exploited. Optional, some CVEs may not contain version 3.0 CVSS scoring.
    :vartype v30exploitability: float 

    :var v2exploitability: Version 2 CVSS exploitability. Reflects the ease and technical means by which the vulnerability can be exploited. Optional, some CVEs may not contain version 2 CVSS scoring.
    :vartype v2exploitability: float 

    :var v31impactScore: Version 3.1 of impact score. Reflects the direct consequence of a successful exploit. Optional, some CVEs may not contain version 3.1 CVSS scoring.
    :vartype v31impactScore: float
    
    :var v30impactScore: Version 3.0 of impact score. Reflects the direct consequence of a successful exploit. Optional, some CVEs may not contain version 3.0 CVSS scoring.
    :vartype v30impactScore: float

    :var v2impactScore: Version 2 of impact score. Reflects the direct consequence of a successful exploit. Optional, some CVEs may not contain version 2 CVSS scoring.
    :vartype v2impactScore: float

    :var score: Contains the CVSS score of the latest CVSS version (3.1 > 3.0 > 2). Where score is an int, severity is a string('LOW','MEDIUM','HIGH','CRITICAL'), and version is a string (V3.1, V3.0, or V2).
    :vartype score: list

    :var v31attackVector: NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL. Present if CVE is scored.
    :vartype v31attackVector: str

    :var v30attackVector: NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL. Present if CVE is scored.
    :vartype v30attackVector: str

    :var v2accessVector: NETWORK, ADJACENT_NETWORK, LOCAL. Present if CVE is scored.
    :vartype v2accesVector: str

    :var v31attackComplexity: HIGH, LOW. Present if CVE is scored. 
    :vartype v31attackComplexity: str

    :var v30attackComplexity: HIGH, LOW. Present if CVE is scored. 
    :vartype v30attackComplexity: str

    :var v2accessComplexity: HIGH, MEDIUM, LOW. Present if CVE is scored. 
    :vartype v2accessComplexity: str

    :var v31privilegesRequired: HIGH, LOW, NONE. Present if CVE is scored.
    :vartype v31privilegesRequired: str

    :var v30privilegesRequired: HIGH, LOW, NONE. Present if CVE is scored.
    :vartype v30privilegesRequired: str

    :var v31userInteraction: NONE, REQUIRED. Present if CVE is scored.
    :vartype v31userInteraction: str

    :var v30userInteraction: NONE, REQUIRED. Present if CVE is scored.
    :vartype v30userInteraction: str

    :var v31scope: UNCHANGED, CHANGED. Present if CVE is scored.
    :vartype v31scope: str

    :var v30scope: UNCHANGED, CHANGED. Present if CVE is scored.
    :vartype v30scope: str
    
    :var v31confidentialityImpact: LOW, MEDIUM, HIGH, CRITICAL. Present if CVE is scored.
    :vartype v31confidentialityImpact: str

    :var v30confidentialityImpact: LOW, MEDIUM, HIGH, CRITICAL. Present if CVE is scored.
    :vartype v30confidentialityImpact: str

    :var v2confidentialityImpact: NONE, PARTIAL, COMPLETE. Present if CVE is scored.
    :vartype v2confidentialityImpact: str

    :var v2authentication: MULTIPLE, SINGLE, NONE. Present if CVE is scored.
    :vartype v2authentication: str

    :var v31integrityImpact: LOW, MEDIUM, HIGH, CRITICAL. Present if CVE is scored.
    :vartype v31integrityImpact: str

    :var v30integrityImpact: LOW, MEDIUM, HIGH, CRITICAL. Present if CVE is scored.
    :vartype v30integrityImpact: str

    :var v2integrityImpact: NONE, PARTIAL, COMPLETE. Present if CVE is scored.
    :vartype v2integrityImpact: str

    :var v31availabilityImpact: LOW, MEDIUM, HIGH, CRITICAL. Present if CVE is scored.
    :vartype v31availabilityImpact: str

    :var v30availabilityImpact: LOW, MEDIUM, HIGH, CRITICAL. Present if CVE is scored.
    :vartype v30availabilityImpact: str

    :var v2availabilityImpact: NONE, PARTIAL, COMPLETE. Present if CVE is scored.
    :vartype v2availabilityImpact: str

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
            self.cpe = self.configurations[0].nodes[0].cpeMatch
        except AttributeError:
            pass
        
        try:
            self.cwe = [x for w in self.weaknesses for x in w.description]
        except AttributeError:
            pass

        try:
            self.url = 'https://nvd.nist.gov/vuln/detail/' + self.id
        except:
            pass
        
        if hasattr(self.metrics, 'cvssMetricV40'):
            self.v40score = self.metrics.cvssMetricV40[0].cvssData.baseScore
            self.v40vector = self.metrics.cvssMetricV40[0].cvssData.vectorString
            self.v40severity = self.metrics.cvssMetricV40[0].cvssData.baseSeverity

        if hasattr(self.metrics, 'cvssMetricV31'):
            self.v31score = self.metrics.cvssMetricV31[0].cvssData.baseScore
            self.v31vector = self.metrics.cvssMetricV31[0].cvssData.vectorString
            self.v31severity = self.metrics.cvssMetricV31[0].cvssData.baseSeverity
            self.v31attackVector = self.metrics.cvssMetricV31[0].cvssData.attackVector
            self.v31attackComplexity = self.metrics.cvssMetricV31[0].cvssData.attackComplexity
            self.v31privilegesRequired = self.metrics.cvssMetricV31[0].cvssData.privilegesRequired
            self.v31userInteraction = self.metrics.cvssMetricV31[0].cvssData.userInteraction
            self.v31scope = self.metrics.cvssMetricV31[0].cvssData.scope
            self.v31confidentialityImpact = self.metrics.cvssMetricV31[0].cvssData.confidentialityImpact
            self.v31integrityImpact = self.metrics.cvssMetricV31[0].cvssData.integrityImpact
            self.v31availabilityImpact= self.metrics.cvssMetricV31[0].cvssData.availabilityImpact

            self.v31exploitability = self.metrics.cvssMetricV31[0].exploitabilityScore
            self.v31impactScore = self.metrics.cvssMetricV31[0].impactScore

        if hasattr(self.metrics, 'cvssMetricV30'):
            self.v30score = self.metrics.cvssMetricV30[0].cvssData.baseScore
            self.v30vector = self.metrics.cvssMetricV30[0].cvssData.vectorString
            self.v30severity = self.metrics.cvssMetricV30[0].cvssData.baseSeverity
            self.v30attackVector = self.metrics.cvssMetricV30[0].cvssData.attackVector
            self.v30attackComplexity = self.metrics.cvssMetricV30[0].cvssData.attackComplexity
            self.v30privilegesRequired = self.metrics.cvssMetricV30[0].cvssData.privilegesRequired
            self.v30userInteraction = self.metrics.cvssMetricV30[0].cvssData.userInteraction
            self.v30scope = self.metrics.cvssMetricV30[0].cvssData.scope
            self.v30confidentialityImpact= self.metrics.cvssMetricV30[0].cvssData.confidentialityImpact
            self.v30integrityImpact = self.metrics.cvssMetricV30[0].cvssData.integrityImpact
            self.v30availabilityImpact= self.metrics.cvssMetricV30[0].cvssData.availabilityImpact

            self.v30exploitability = self.metrics.cvssMetricV30[0].exploitabilityScore
            self.v30impactScore = self.metrics.cvssMetricV30[0].impactScore        

        if hasattr(self.metrics, 'cvssMetricV2'):
            self.v2score = self.metrics.cvssMetricV2[0].cvssData.baseScore
            self.v2vector = self.metrics.cvssMetricV2[0].cvssData.vectorString
            self.v2severity = self.metrics.cvssMetricV2[0].baseSeverity
            self.v2accessVector = self.metrics.cvssMetricV2[0].cvssData.accessVector
            self.v2accessComplexity = self.metrics.cvssMetricV2[0].cvssData.accessComplexity
            self.v2authentication = self.metrics.cvssMetricV2[0].cvssData.authentication
            self.v2confidentialityImpact = self.metrics.cvssMetricV2[0].cvssData.confidentialityImpact
            self.v2integrityImpact = self.metrics.cvssMetricV2[0].cvssData.integrityImpact
            self.v2availabilityImpact = self.metrics.cvssMetricV2[0].cvssData.availabilityImpact
            self.v2exploitability = self.metrics.cvssMetricV2[0].exploitabilityScore
            self.v2impactScore = self.metrics.cvssMetricV2[0].impactScore
        
        # Prefer the base score version to V3, if it isn't available use V2.
        # If no score is present, then set it to None.
        if hasattr(self.metrics, 'cvssMetricV40'):
            self.score = ['V40', self.v40score, self.v40severity]
        elif hasattr(self.metrics, 'cvssMetricV31'):
            self.score = ['V31', self.v31score, self.v31severity]
        elif hasattr(self.metrics, 'cvssMetricV30'):
            self.score = ['V30', self.v30score, self.v30severity]
        elif hasattr(self.metrics, 'cvssMetricV2'):
            self.score = ['V2', self.v2score, self.v2severity]
        else:
            self.score = [None, None, None]

def __convert(product: Literal["cve", "cpe", "MatchString"], CVEID: Any) -> Union[CVE, CPE, MatchString]:
    """Convert the JSON response to a referenceable object."""
    if product == 'cve':
        vuln = json.loads(json.dumps(CVEID), object_hook= CVE)
        vuln.getvars()
        return vuln
    elif product == 'cpe':
        cpeEntry = json.loads(json.dumps(CVEID), object_hook= CPE)
        return cpeEntry 
    else:
        matchString = json.loads(json.dumps(CVEID), object_hook= MatchString)
        return matchString
