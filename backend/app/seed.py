import asyncio
from sqlalchemy import select
from .database import engine, Base, AsyncSessionLocal
from . import models, auth

USERS_TO_SEED = [
    {
        "email": "admin@threatlens.local",
        "password": "admin123",
        "role": models.RoleEnum.admin,
        "name": "Marcus Vance (Administrator)"
    },
    {
        "email": "analyst@threatlens.local",
        "password": "analyst123",
        "role": models.RoleEnum.soc_analyst,
        "name": "SOC Analyst (Triage & Enrichment)"
    },
    {
        "email": "responder@threatlens.local",
        "password": "responder123",
        "role": models.RoleEnum.incident_responder,
        "name": "Daniel Okafor (Incident Responder)"
    },
    {
        "email": "hunter@threatlens.local",
        "password": "hunter123",
        "role": models.RoleEnum.threat_hunter,
        "name": "Mei Lin Tan (Threat Hunter)"
    },
    {
        "email": "executive@threatlens.local",
        "password": "executive123",
        "role": models.RoleEnum.executive,
        "name": "Rachel Adeyemi (CISO / Executive)"
    },
    {
        "email": "engineer@threatlens.local",
        "password": "engineer123",
        "role": models.RoleEnum.security_engineer,
        "name": "Kavita Patel (Security Engineer)"
    }
]

async def seed_database():
    # 1. Create all tables asynchronously
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    async with AsyncSessionLocal() as db:
        # 2. Create PRD Role Users
        for user_data in USERS_TO_SEED:
            result = await db.execute(select(models.User).where(models.User.email == user_data["email"]))
            existing_user = result.scalar_one_or_none()
            if not existing_user:
                db.add(models.User(
                    email=user_data["email"],
                    hashed_password=auth.get_password_hash(user_data["password"]),
                    role=user_data["role"]
                ))
                print(f"✅ Created {user_data['name']} -> {user_data['email']}")
            else:
                # Update role if needed
                existing_user.role = user_data["role"]
            
        # 3. Seed Dummy Indicators
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
        print("✅ Database seeded with PRD role personas and indicators successfully!")

if __name__ == "__main__":
    asyncio.run(seed_database())
