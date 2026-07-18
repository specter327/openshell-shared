from .base import Certificate

from ..identity.entity import EntityIdentity

from ..standards.certificates.types import CertificateType


class ManagerCertificate(Certificate):
    """
    Certificate of Manager (CG).

    Emitido por la Root Authority para autorizar
    a una entidad como Gestor del ecosistema OpenShell.
    """

    CERTIFICATE_TYPE = CertificateType.MANAGER_AUTHORIZATION

    @classmethod
    def create(
        cls,
        issuer: EntityIdentity,
        subject: EntityIdentity,
        expires_at: int | None = None,
    ) -> "ManagerCertificate":

        certificate = super().create(
            issuer=issuer,
            subject=subject,
            certificate_type=cls.CERTIFICATE_TYPE,
            expires_at=expires_at,
        )

        certificate.__class__ = cls

        return certificate

    @classmethod
    def from_dict(
        cls,
        data: dict,
    ) -> "ManagerCertificate":

        certificate = super().from_dict(data)

        certificate.__class__ = cls

        return certificate

    @classmethod
    def from_json(
        cls,
        data: str,
    ) -> "ManagerCertificate":

        certificate = super().from_json(data)

        certificate.__class__ = cls

        return certificate