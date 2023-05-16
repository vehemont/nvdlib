import asyncio

import aiohttp

from nvdlib import searchCVE


async def main():
    packages = ['django', 'redis', 'requests']
    async with aiohttp.ClientSession() as session:
        tasks = [searchCVE(session, keywordSearch=package) for package in packages]
        return await asyncio.gather(*tasks)

if __name__ == "__main__":
    results = asyncio.run(main())
    print(results)
