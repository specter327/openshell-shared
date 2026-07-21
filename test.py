from openshell_shared.standards.passports.models import Passport, PASSPORT_TYPE
from uuid6 import uuid7
p=Passport.create(
  domain_uid=uuid7(),
  protocol=PASSPORT_TYPE.OPEN.value,
  predefined_role="PROPIETARY"
)
print(p)
