import asyncio

from openshell_shared.communication.manager import (
    CommunicationManager
)

from openshell_shared.communication.models import RoleType

async def main():

    manager = CommunicationManager(
        mode=RoleType.SERVER.value
    )

    await manager.start()

    print("Server started")

    while True:

        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())