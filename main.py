from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from auth_app.schemas import StandardResponse
from auth_app.urls import router
from auth_app.database import engine, Base
from v2.admin_router import router as admin_router
from fastapi.middleware.cors import CORSMiddleware

def create_tables():
    Base.metadata.create_all(bind=engine)


app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "message": exc.detail,
            "data": None
        },
    )




app.include_router(router, prefix="/auth")
app.include_router(admin_router, prefix="/auth")

# Base.metadata.create_all(bind=engine)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
