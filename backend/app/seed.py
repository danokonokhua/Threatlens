import asyncio
from sqlalchemy import select
from .database import engine, Base, AsyncSessionLocal
from . import models, auth

async def seed_database():
    # 1. Create all tables asynchronously
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    async with AsyncSessionLocal() as db:
        # 2. Create Admin User
        result = await db.execute(select(models.User).where(models.User.email == "admin@threatlens.local"))
        admin = result.scalar_one_or_none()
        if not admin:
            db.add(models.User(
                email="admin@threatlens.local",
                hashed_password=auth.get_password_hash("admin123"),
                role=models.RoleEnum.admin
            ))
            print("✅ Created admin@threatlens.local (password: admin123)")
            
        # 3. Create Analyst User
        result = await db.execute(select(models.User).where(models.User.email == "analyst@threatlens.local"))
        analyst = result.scalar_one_or_none()
        if not analyst:
            db.add(models.User(
                email="analyst@threatlens.local",
                hashed_password=auth.get_password_hash("analyst123"),
                role=models.RoleEnum.soc_analyst
            ))
            print("✅ Created analyst@threatlens.local (password: analyst123)")
            
        # 4. Seed Dummy Indicators
        indicators = [
            {"value": "185.220.101.4", "type": "ip", "severity_score": 85, "confidence": 90},
            {"value": "malicious-domain.com", "type": "domain", "severity_score": 70, "confidence": 80},
            {"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "type": "hash_sha256", "severity_score": 95, "confidence": 99},
        ]
        
        for ioc in indicators:
            result = await db.execute(select(models.Indicator).where(models.Indicator.value == ioc["value"]))
            if not result.scalar_one_or_none():
                db.add(models.Indicator(**ioc))
                
        await db.commit()
        print("✅ Database seeded with dummy indicators successfully!")

if __name__ == "__main__":
    asyncio.run(seed_database())