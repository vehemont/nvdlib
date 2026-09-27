import json
from typing import Any, Union, Literal

# CVSS 4.0 cvssData fields copied onto a CVE when that CVE includes them.
# Supplemental names keep the capitalization used by the NVD schema.
_V40_DATA_FIELDS = (
    'attackVector',
    'attackComplexity',
    'attackRequirements',
    'privilegesRequired',
    'userInteraction',
    'vulnConfidentialityImpact',
    'vulnIntegrityImpact',
    'vulnAvailabilityImpact',
    'subConfidentialityImpact',
    'subIntegrityImpact',
    'subAvailabilityImpact',
    'exploitMaturity',
    'confidentialityRequirement',
    'integrityRequirement',
    'availabilityRequirement',
    'modifiedAttackVector',
    'modifiedAttackComplexity',
    'modifiedAttackRequirements',
    'modifiedPrivilegesRequired',
    'modifiedUserInteraction',
    'modifiedVulnConfidentialityImpact',
    'modifiedVulnIntegrityImpact',
    'modifiedVulnAvailabilityImpact',
    'modifiedSubConfidentialityImpact',
    'modifiedSubIntegrityImpact',
    'modifiedSubAvailabilityImpact',
    'threatScore',
    'threatSeverity',
    'environmentalScore',
    'environmentalSeverity',
    'Safety',
    'Automatable',
    'Recovery',
    'valueDensity',
    'vulnerabilityResponseEffort',
    'providerUrgency',
)


def _cvss_primary(metrics):
    """Return the Primary CVSS metric, or the first entry when none is marked Primary."""
    for metric in metrics:
        if getattr(metric, 'type', None) == 'Primary':
            return metric
    return metrics[0]


class CPE:
    """JSON dump class for CPEs

    :var deprecated: Indicates whether CPE has been deprecated
    :vartype deprecated: bool

    :var cpeName: CPE URI name
    :vartype name: str

    :var cpeNameId: CPE UUID
    :vartype cpeNameId: str

    :var lastModified: CPE modification date
    :vartype lastModified: str

    :var created: CPE creation date
    :vartype created: str

    :var titles: List of available titles for the CPE
    :vartype title: list

    :var refs: Optional, reference links for the CPE
    :vartype refs: list

    :var deprecatedBy: If deprecated=true, one or more CPE that replace this one
    :vartype deprecatedby: list

    :var deprecates: Optional, one or more CPE that this CPE replaces
    :vartype deprecates: list
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

    def __getattr__(self, item):
        try:
            return self.__dict__[item]
        except KeyError:
            classname = type(self).__name__
            msg = f'{classname!r} object has no attribute {item!r}'
            raise AttributeError(msg)


class MatchString:
    """JSON dump class for CPE match strings

    :var matchCriteriaId: UUID match criteria
    :vartype matchCriteriaId: str

    :var criteria: CPE name
    :vartype criteria: str

    :var lastModified: Match string modification date
    :vartype lastModified: str

    :var cpeLastModified: CPE modification date
    :vartype cpeLastModified: str 

    :var created: CPE creation date
    :vartype created: str

    :var status: CPE active status
    :vartype status: str

    :var versionStartIncluding: Optional, only exists if the match string is a version range.
    :vartype versionStartIncluding: str

    :var versionStartExcluding: Optional, only exists if the match string is a version range.
    :vartype versionStartExcluding: str

    :var versionEndIncluding: Optional, only exists if the match string is a version range.
    :vartype versionEndIncluding: str

    :var versionEndExcluding: Optional, only exists if the match string is a version range.
    :vartype versionEndExcluding: str
    
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

class CVEHistory:
    """JSON dump class for CVE change history events

    :var cveId: CVE ID
    :vartype cveId: str

    :var eventName: Type of change event, such as 'Initial Analysis' or 'CVE Modified'.
    :vartype eventName: str

    :var cveChangeId: UUID of the change event
    :vartype cveChangeId: str

    :var sourceIdentifier: Source of the change event
    :vartype sourceIdentifier: str

    :var created: Date and time of the change
    :vartype created: str

    :var details: List of changes made in the event
    :vartype details: list
    """

    def __init__(self, response):
        vars(self).update(response)

    def __getattr__(self, item):
        try:
            return self.__dict__[item]
        except KeyError:
            classname = type(self).__name__
            msg = f'{classname!r} object has no attribute {item!r}'
            raise AttributeError(msg)


class Source:
    """JSON dump class for NVD data sources

    :var name: Source name
    :vartype name: str

    :var contactEmail: Email address used by the CVE Program to identify the source
    :vartype contactEmail: str

    :var sourceIdentifiers: All source identifiers linked to the source
    :vartype sourceIdentifiers: list

    :var lastModified: Source modification date
    :vartype lastModified: str

    :var created: Source creation date
    :vartype created: str
    """

    def __init__(self, response):
        vars(self).update(response)

    def __getattr__(self, item):
        try:
            return self.__dict__[item]
        except KeyError:
            classname = type(self).__name__
            msg = f'{classname!r} object has no attribute {item!r}'
            raise AttributeError(msg)


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

    :var cisaExploitAdd: Optional, only exists if the CVE is listed in the Known Exploited Vulnerabilities (KEV) catalog.
    :vartype cisaExploitAdd: str

    :var cisaActionDue: Optional, only exists if the CVE is listed in the Known Exploited Vulnerabilities (KEV) catalog.
    :vartype cisaActionDue: str

    :var cisaRequiredAction: Optional, only exists if the CVE is listed in the Known Exploited Vulnerabilities (KEV) catalog.
    :vartype cisaRequiredAction: str

    :var cisaVulnerabilityName: Optional, only exists if the CVE is listed in the Known Exploited Vulnerabilities (KEV) catalog.
    :vartype cisaVulnerabilityName: str

    :var cveTags: Optional, tags such as 'disputed' provided by a source.
    :vartype cveTags: list[CVE]

    :var affected: Optional, affected vendors, products, and versions provided by a source.
    :vartype affected: list[CVE]

    :var vendorComments: Optional, official vendor comments on the CVE.
    :vartype vendorComments: list[CVE]

    :var evaluatorComment: Optional, additional context from the NVD analysis.
    :vartype evaluatorComment: str

    :var evaluatorImpact: Optional, additional context on the impact from the NVD analysis.
    :vartype evaluatorImpact: str

    :var evaluatorSolution: Optional, additional context on the solution from the NVD analysis.
    :vartype evaluatorSolution: str

    :var descriptions: CVE descriptions. Includes other languages.
    :vartype descriptions: list[CVE] 

    :var metrics: Class attribute containing scoring lists (cvssMetricV40 / V31 / V30 / V2). May also contain SSVC data (ssvcV203).
    :vartype metrics: CVE class

    :var weaknesses: Contains relevant CWE information.
    :vartype weaknesses: list[CVE]

    :var configurations: List containing usually a single element of CPE information.
    :vartype configuration: list[CVE]

    :var references: CVE reference links
    :vartype references: list[CVE]

    :var cwe: Common Weakness Enumeration Specification (CWE)
    :vartype cwe: list[dict]

    :var url: Link to additional details on nvd.nist.gov for that CVE.
    :vartype url: str

    :var cpe: Common Platform Enumeration (CPE) matches assigned to the CVE, from every configuration node.
    :vartype cpe: list[CVE]

    :var ssvc: Stakeholder-Specific Vulnerability Categorization (SSVC) assessments. Optional, only exists if the CVE includes SSVC data.
    :vartype ssvc: list[CVE]

    :var v31score: Float that contains the V3.1 CVSS base score (0 - 10). Optional, some CVEs may not contain version 3.1 CVSS scoring.
    :vartype v31score: float
    
    :var v30score: Float that contains the V3.0 CVSS base score (0 - 10). Optional, some CVEs may not contain version 3.0 CVSS scoring.
    :vartype v30score: float
    
    :var v2score: Float that contains the V2 CVSS base score (0 - 10). Optional, some CVEs may not contain version 2 CVSS scoring.
    :vartype v2score: float

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

    :var score: Contains the CVSS score of the latest CVSS version (4.0 > 3.1 > 3.0 > 2). Where score is a float, severity is a string('LOW','MEDIUM','HIGH','CRITICAL'), and version is a string (V40, V31, V30, or V2). Each version uses the Primary metric when one is present, otherwise the first metric.
    :vartype score: list[str]

    :var v40score: Float that contains the V4.0 CVSS base score (0 - 10). Optional, some CVEs may not contain version 4.0 CVSS scoring. Uses the Primary metric when one is present.
    :vartype v40score: float

    :var v40vector: Version 4.0 of the CVSS score represented as a vector string. Optional, some CVEs may not contain version 4.0 CVSS scoring.
    :vartype v40vector: str

    :var v40severity: LOW, MEDIUM, HIGH, CRITICAL. Optional, some CVEs may not contain version 4.0 CVSS scoring.
    :vartype v40severity: str

    :var v40attackVector: NETWORK, ADJACENT, LOCAL, PHYSICAL. Set when the CVE includes this CVSS 4.0 field.
    :vartype v40attackVector: str

    :var v40attackComplexity: HIGH, LOW. Set when the CVE includes this CVSS 4.0 field.
    :vartype v40attackComplexity: str

    :var v40attackRequirements: NONE, PRESENT. Set when the CVE includes this CVSS 4.0 field.
    :vartype v40attackRequirements: str

    :var v40privilegesRequired: HIGH, LOW, NONE. Set when the CVE includes this CVSS 4.0 field.
    :vartype v40privilegesRequired: str

    :var v40userInteraction: NONE, PASSIVE, ACTIVE. Set when the CVE includes this CVSS 4.0 field.
    :vartype v40userInteraction: str

    :var v40vulnConfidentialityImpact: NONE, LOW, HIGH. Vulnerable-system impact. Set when the CVE includes this CVSS 4.0 field.
    :vartype v40vulnConfidentialityImpact: str

    :var v40vulnIntegrityImpact: NONE, LOW, HIGH. Vulnerable-system impact. Set when the CVE includes this CVSS 4.0 field.
    :vartype v40vulnIntegrityImpact: str

    :var v40vulnAvailabilityImpact: NONE, LOW, HIGH. Vulnerable-system impact. Set when the CVE includes this CVSS 4.0 field.
    :vartype v40vulnAvailabilityImpact: str

    :var v40subConfidentialityImpact: NONE, LOW, HIGH. Subsequent-system impact. Set when the CVE includes this CVSS 4.0 field.
    :vartype v40subConfidentialityImpact: str

    :var v40subIntegrityImpact: NONE, LOW, HIGH. Subsequent-system impact. Set when the CVE includes this CVSS 4.0 field.
    :vartype v40subIntegrityImpact: str

    :var v40subAvailabilityImpact: NONE, LOW, HIGH. Subsequent-system impact. Set when the CVE includes this CVSS 4.0 field.
    :vartype v40subAvailabilityImpact: str

    :var v40exploitMaturity: UNREPORTED, PROOF_OF_CONCEPT, ATTACKED, NOT_DEFINED. Other CVSS 4.0 threat, environmental, and supplemental fields are copied the same way when present: requirement fields, every modified field, threatScore, threatSeverity, environmentalScore, environmentalSeverity, Safety, Automatable, Recovery, valueDensity, vulnerabilityResponseEffort, and providerUrgency. NOT_DEFINED is kept. Missing fields are left unset. There is no exploitability or impact score for version 4.0.
    :vartype v40exploitMaturity: str

    :var v31attackVector: NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL. Present if CVE is scored.
    :vartype v31attackVector: str

    :var v30attackVector: NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL. Present if CVE is scored.
    :vartype v30attackVector: str

    :var v2accessVector: NETWORK, ADJACENT_NETWORK, LOCAL. Present if CVE is scored.
    :vartype v2accessVector: str

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
    
    :var v31confidentialityImpact: NONE, LOW, HIGH. Present if CVE is scored.
    :vartype v31confidentialityImpact: str

    :var v30confidentialityImpact: NONE, LOW, HIGH. Present if CVE is scored.
    :vartype v30confidentialityImpact: str

    :var v2confidentialityImpact: NONE, PARTIAL, COMPLETE. Present if CVE is scored.
    :vartype v2confidentialityImpact: str

    :var v2authentication: MULTIPLE, SINGLE, NONE. Present if CVE is scored.
    :vartype v2authentication: str

    :var v31integrityImpact: NONE, LOW, HIGH. Present if CVE is scored.
    :vartype v31integrityImpact: str

    :var v30integrityImpact: NONE, LOW, HIGH. Present if CVE is scored.
    :vartype v30integrityImpact: str

    :var v2integrityImpact: NONE, PARTIAL, COMPLETE. Present if CVE is scored.
    :vartype v2integrityImpact: str

    :var v31availabilityImpact: NONE, LOW, HIGH. Present if CVE is scored.
    :vartype v31availabilityImpact: str

    :var v30availabilityImpact: NONE, LOW, HIGH. Present if CVE is scored.
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

    def __getattr__(self, item):
        try:
            return self.__dict__[item]
        except KeyError:
            classname = type(self).__name__
            msg = f'{classname!r} object has no attribute {item!r}'
            raise AttributeError(msg)

    def getvars(self):
        try:
            self.cpe = [match for config in self.configurations for node in config.nodes for match in node.cpeMatch]
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
        
        if hasattr(self.metrics, 'cvssMetricV40') and self.metrics.cvssMetricV40:
            cvss = _cvss_primary(self.metrics.cvssMetricV40).cvssData
            if hasattr(cvss, 'baseScore'):
                self.v40score = cvss.baseScore
            if hasattr(cvss, 'vectorString'):
                self.v40vector = cvss.vectorString
            if hasattr(cvss, 'baseSeverity'):
                self.v40severity = cvss.baseSeverity
            for field in _V40_DATA_FIELDS:
                if hasattr(cvss, field):
                    setattr(self, 'v40' + field, getattr(cvss, field))

        for name in vars(self.metrics):
            if name.startswith('ssvc'):
                self.ssvc = getattr(self.metrics, name)

        if hasattr(self.metrics, 'cvssMetricV31'):
            v31 = _cvss_primary(self.metrics.cvssMetricV31)
            self.v31score = v31.cvssData.baseScore
            self.v31vector = v31.cvssData.vectorString
            self.v31severity = v31.cvssData.baseSeverity
            self.v31attackVector = v31.cvssData.attackVector
            self.v31attackComplexity = v31.cvssData.attackComplexity
            self.v31privilegesRequired = v31.cvssData.privilegesRequired
            self.v31userInteraction = v31.cvssData.userInteraction
            self.v31scope = v31.cvssData.scope
            self.v31confidentialityImpact = v31.cvssData.confidentialityImpact
            self.v31integrityImpact = v31.cvssData.integrityImpact
            self.v31availabilityImpact= v31.cvssData.availabilityImpact

            self.v31exploitability = v31.exploitabilityScore
            self.v31impactScore = v31.impactScore

        if hasattr(self.metrics, 'cvssMetricV30'):
            v30 = _cvss_primary(self.metrics.cvssMetricV30)
            self.v30score = v30.cvssData.baseScore
            self.v30vector = v30.cvssData.vectorString
            self.v30severity = v30.cvssData.baseSeverity
            self.v30attackVector = v30.cvssData.attackVector
            self.v30attackComplexity = v30.cvssData.attackComplexity
            self.v30privilegesRequired = v30.cvssData.privilegesRequired
            self.v30userInteraction = v30.cvssData.userInteraction
            self.v30scope = v30.cvssData.scope
            self.v30confidentialityImpact= v30.cvssData.confidentialityImpact
            self.v30integrityImpact = v30.cvssData.integrityImpact
            self.v30availabilityImpact= v30.cvssData.availabilityImpact

            self.v30exploitability = v30.exploitabilityScore
            self.v30impactScore = v30.impactScore        

        if hasattr(self.metrics, 'cvssMetricV2'):
            v2 = _cvss_primary(self.metrics.cvssMetricV2)
            self.v2score = v2.cvssData.baseScore
            self.v2vector = v2.cvssData.vectorString
            self.v2severity = v2.baseSeverity
            self.v2accessVector = v2.cvssData.accessVector
            self.v2accessComplexity = v2.cvssData.accessComplexity
            self.v2authentication = v2.cvssData.authentication
            self.v2confidentialityImpact = v2.cvssData.confidentialityImpact
            self.v2integrityImpact = v2.cvssData.integrityImpact
            self.v2availabilityImpact = v2.cvssData.availabilityImpact
            self.v2exploitability = v2.exploitabilityScore
            self.v2impactScore = v2.impactScore
        
        # Prefer the latest CVSS version.
        # If no score is present, then set it to None.
        if hasattr(self, 'v40score'):
            self.score = ['V40', self.v40score, self.v40severity]
        elif hasattr(self.metrics, 'cvssMetricV31'):
            self.score = ['V31', self.v31score, self.v31severity]
        elif hasattr(self.metrics, 'cvssMetricV30'):
            self.score = ['V30', self.v30score, self.v30severity]
        elif hasattr(self.metrics, 'cvssMetricV2'):
            self.score = ['V2', self.v2score, self.v2severity]
        else:
            self.score = [None, None, None]

def __convert(product: Literal["cve", "cpe", "MatchString", "cveHistory", "source"], CVEID: Any) -> Union[CVE, CPE, MatchString, CVEHistory, Source]:
    """Convert the JSON response to a referenceable object."""
    if product == 'cve':
        vuln = json.loads(json.dumps(CVEID), object_hook= CVE)
        vuln.getvars()
        return vuln
    elif product == 'cpe':
        cpeEntry = json.loads(json.dumps(CVEID), object_hook= CPE)
        return cpeEntry 
    elif product == 'cveHistory':
        change = json.loads(json.dumps(CVEID), object_hook= CVEHistory)
        return change
    elif product == 'source':
        source = json.loads(json.dumps(CVEID), object_hook= Source)
        return source
    else:
        matchString = json.loads(json.dumps(CVEID), object_hook= MatchString)
        return matchString
