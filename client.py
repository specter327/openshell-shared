import asyncio

from openshell_shared.communication.manager import (
    CommunicationManager
)

from openshell_shared.communication.models import RoleType


async def main():

    manager = CommunicationManager(
        mode=RoleType.CLIENT.value
    )

    await manager.start()

    connection_uid = await manager._ws.connect(
        "127.0.0.1",
        40000
    )

    print("Connected:", connection_uid)
    await manager._flow.send_datapackage(
        connection_uid,
        {
            "hello":"world"
        }
    )
    while True:

        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())