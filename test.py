import openshell_shared

E1=openshell_shared.identity.entity.EntityIdentity.create()
E2=openshell_shared.identity.entity.EntityIdentity.create()
D1=openshell_shared.domain.domain.DomainIdentity.create()

print(f"Entity1:")
print(E1)

print(f"Entity2:")
print(E2)

print(f"Domain1:")
print(D1)

MC1=openshell_shared.certificates.manager.ManagerCertificate.create(issuer=E1, subject=E2)

print(f"Manager Certificate emmited by: Entity1, to: Entity2:")
print(MC1)

CAD1=openshell_shared.certificates.domain.DomainManagementCertificate.create(issuer=E1, subject=E2, domain=D1)

print(f"Domain Management Certificate emmited by: Entity1, to: Entity2, to domain: Domain1:")
print(CAD1)

print(f"CAD1 dump:")
print(CAD1.to_json())

print(f"CAD1 verification:")
print(CAD1.verify())

CAD1._domain = openshell_shared.domain.domain.DomainIdentity.create()
print(f"CAD1 modified:")
print(CAD1.to_json())

print(f"CAD1 verification:")
print(CAD1.verify())