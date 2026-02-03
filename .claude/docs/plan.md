# 로그인 기능 구현 - 세부 개발 계획

## 프로젝트 개요

풀스택 웹 애플리케이션에 사용자 인증(로그인/회원가입) 기능을 추가합니다.
JWT 기반 토큰 인증 방식을 사용하며, 각 작업을 최소 단위로 분해하여 단계별로 진행합니다.

---

# Phase 1: 데이터베이스 작업 (db-agent)

## 1.1 환경 준비

### 1.1.1 필요한 패키지 확인
- **담당**: `db-agent`
- **파일**: 없음 (확인 작업)
- **작업**:
  - `backend/requirements.txt` 파일 확인
  - SQLAlchemy가 설치되어 있는지 확인
  - 없으면 추가 필요

### 1.1.2 models 디렉토리 확인
- **담당**: `db-agent`
- **파일**: `backend/app/models/`
- **작업**:
  - `__init__.py` 파일 존재 확인
  - 기존 모델 구조 파악

---

## 1.2 User 모델 생성

### 1.2.1 기본 파일 생성 및 임포트
- **담당**: `db-agent`
- **Skill**: `DB-model`
- **파일**: `backend/app/models/user.py` (새로 생성)
- **작업**:
  ```python
  from sqlalchemy import Column, Integer, String, DateTime
  from sqlalchemy.sql import func
  from app.database import Base
  ```
- **체크포인트**: 파일 생성 및 임포트 에러 없음

### 1.2.2 User 클래스 뼈대 작성
- **담당**: `db-agent`
- **Skill**: `DB-model`
- **파일**: `backend/app/models/user.py`
- **작업**:
  ```python
  class User(Base):
      __tablename__ = "users"
  ```
- **체크포인트**: 클래스 정의 완료

### 1.2.3 Primary Key 필드 추가
- **담당**: `db-agent`
- **Skill**: `DB-model`
- **파일**: `backend/app/models/user.py`
- **작업**:
  ```python
  id = Column(Integer, primary_key=True, index=True, autoincrement=True)
  ```
- **체크포인트**: id 필드 추가 완료

### 1.2.4 username 필드 추가
- **담당**: `db-agent`
- **Skill**: `DB-model`
- **파일**: `backend/app/models/user.py`
- **작업**:
  ```python
  username = Column(String(50), unique=True, nullable=False, index=True)
  ```
- **체크포인트**: username 필드 추가 완료

### 1.2.5 email 필드 추가
- **담당**: `db-agent`
- **Skill**: `DB-model`
- **파일**: `backend/app/models/user.py`
- **작업**:
  ```python
  email = Column(String(100), unique=True, nullable=False, index=True)
  ```
- **체크포인트**: email 필드 추가 완료

### 1.2.6 password_hash 필드 추가
- **담당**: `db-agent`
- **Skill**: `DB-model`
- **파일**: `backend/app/models/user.py`
- **작업**:
  ```python
  password_hash = Column(String(255), nullable=False)
  ```
- **체크포인트**: password_hash 필드 추가 완료

### 1.2.7 created_at 필드 추가
- **담당**: `db-agent`
- **Skill**: `DB-model`
- **파일**: `backend/app/models/user.py`
- **작업**:
  ```python
  created_at = Column(DateTime(timezone=True), server_default=func.now())
  ```
- **체크포인트**: created_at 필드 추가 완료

### 1.2.8 updated_at 필드 추가
- **담당**: `db-agent`
- **Skill**: `DB-model`
- **파일**: `backend/app/models/user.py`
- **작업**:
  ```python
  updated_at = Column(DateTime(timezone=True), onupdate=func.now())
  ```
- **체크포인트**: updated_at 필드 추가 완료

### 1.2.9 __repr__ 메서드 추가
- **담당**: `db-agent`
- **Skill**: `DB-model`
- **파일**: `backend/app/models/user.py`
- **작업**:
  ```python
  def __repr__(self):
      return f"<User(id={self.id}, username='{self.username}')>"
  ```
- **체크포인트**: 디버깅용 메서드 추가 완료

### 1.2.10 models/__init__.py 업데이트
- **담당**: `db-agent`
- **Skill**: `DB-model`
- **파일**: `backend/app/models/__init__.py`
- **작업**:
  ```python
  from .user import User
  ```
- **체크포인트**: User 모델 export 완료

### 1.2.11 main.py에서 테이블 생성 확인
- **담당**: `db-agent`
- **Skill**: `DB-model`
- **파일**: `backend/app/main.py`
- **작업**:
  - `Base.metadata.create_all(bind=engine)` 존재 확인
  - 없으면 추가
- **체크포인트**: 테이블 자동 생성 설정 완료

---

## 1.3 CRUD 디렉토리 및 파일 준비

### 1.3.1 crud 디렉토리 생성
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/` (디렉토리)
- **작업**:
  - crud 디렉토리가 없으면 생성
  - `__init__.py` 파일 생성
- **체크포인트**: 디렉토리 구조 준비 완료

### 1.3.2 user.py 파일 생성 및 임포트
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py` (새로 생성)
- **작업**:
  ```python
  from sqlalchemy.orm import Session
  from sqlalchemy.exc import IntegrityError
  from app.models.user import User
  from typing import Optional
  ```
- **체크포인트**: 파일 및 임포트 준비 완료

---

## 1.4 create_user 함수 구현

### 1.4.1 함수 시그니처 작성
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  def create_user(
      db: Session,
      username: str,
      email: str,
      password_hash: str
  ) -> User:
      """새로운 사용자를 생성합니다."""
      pass
  ```
- **체크포인트**: 함수 시그니처 완료

### 1.4.2 username/email 소문자 변환 로직 추가
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  username = username.lower().strip()
  email = email.lower().strip()
  ```
- **체크포인트**: 입력값 정규화 완료

### 1.4.3 User 객체 생성
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  db_user = User(
      username=username,
      email=email,
      password_hash=password_hash
  )
  ```
- **체크포인트**: User 객체 생성 로직 완료

### 1.4.4 DB에 추가 및 커밋
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  db.add(db_user)
  db.commit()
  db.refresh(db_user)
  return db_user
  ```
- **체크포인트**: DB 저장 로직 완료

### 1.4.5 IntegrityError 예외 처리
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  try:
      # 기존 코드
  except IntegrityError as e:
      db.rollback()
      raise ValueError("Username or email already exists") from e
  ```
- **체크포인트**: 중복 에러 처리 완료

---

## 1.5 get_user_by_username 함수 구현

### 1.5.1 함수 시그니처 작성
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  def get_user_by_username(
      db: Session,
      username: str
  ) -> Optional[User]:
      """username으로 사용자를 조회합니다."""
      pass
  ```
- **체크포인트**: 함수 시그니처 완료

### 1.5.2 username 소문자 변환
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  username = username.lower().strip()
  ```
- **체크포인트**: 입력값 정규화 완료

### 1.5.3 쿼리 작성 및 반환
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  return db.query(User).filter(User.username == username).first()
  ```
- **체크포인트**: 조회 로직 완료

---

## 1.6 get_user_by_email 함수 구현

### 1.6.1 함수 시그니처 작성
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  def get_user_by_email(
      db: Session,
      email: str
  ) -> Optional[User]:
      """email로 사용자를 조회합니다."""
      pass
  ```
- **체크포인트**: 함수 시그니처 완료

### 1.6.2 email 소문자 변환
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  email = email.lower().strip()
  ```
- **체크포인트**: 입력값 정규화 완료

### 1.6.3 쿼리 작성 및 반환
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  return db.query(User).filter(User.email == email).first()
  ```
- **체크포인트**: 조회 로직 완료

---

## 1.7 get_user_by_id 함수 구현

### 1.7.1 함수 시그니처 작성
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  def get_user_by_id(
      db: Session,
      user_id: int
  ) -> Optional[User]:
      """user_id로 사용자를 조회합니다."""
      pass
  ```
- **체크포인트**: 함수 시그니처 완료

### 1.7.2 쿼리 작성 및 반환
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/user.py`
- **작업**:
  ```python
  return db.query(User).filter(User.id == user_id).first()
  ```
- **체크포인트**: 조회 로직 완료

### 1.7.3 crud/__init__.py 업데이트
- **담당**: `db-agent`
- **Skill**: `DB-crud`
- **파일**: `backend/app/crud/__init__.py`
- **작업**:
  ```python
  from .user import (
      create_user,
      get_user_by_username,
      get_user_by_email,
      get_user_by_id
  )
  ```
- **체크포인트**: CRUD 함수 export 완료

---

## 1.8 데이터베이스 테스트 작성

### 1.8.1 테스트 디렉토리 준비
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: `backend/tests/` (디렉토리)
- **작업**:
  - tests 디렉토리 없으면 생성
  - `__init__.py` 생성
  - `conftest.py` 생성 (테스트용 DB 세션)
- **체크포인트**: 테스트 환경 준비 완료

### 1.8.2 conftest.py 작성 - 임포트
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: `backend/tests/conftest.py`
- **작업**:
  ```python
  import pytest
  from sqlalchemy import create_engine
  from sqlalchemy.orm import sessionmaker
  from app.database import Base
  ```
- **체크포인트**: 임포트 완료

### 1.8.3 conftest.py 작성 - 테스트 DB 엔진
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: `backend/tests/conftest.py`
- **작업**:
  ```python
  @pytest.fixture(scope="function")
  def db_session():
      # 메모리 SQLite DB 생성
      engine = create_engine("sqlite:///:memory:")
      Base.metadata.create_all(bind=engine)
      SessionLocal = sessionmaker(bind=engine)
      session = SessionLocal()
      yield session
      session.close()
  ```
- **체크포인트**: 테스트 DB fixture 완료

### 1.8.4 test_user_crud.py 파일 생성 및 임포트
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: `backend/tests/test_user_crud.py` (새로 생성)
- **작업**:
  ```python
  import pytest
  from app.crud.user import (
      create_user,
      get_user_by_username,
      get_user_by_email,
      get_user_by_id
  )
  ```
- **체크포인트**: 테스트 파일 준비 완료

### 1.8.5 테스트 1: User 생성 성공
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: `backend/tests/test_user_crud.py`
- **작업**:
  ```python
  def test_create_user_success(db_session):
      user = create_user(
          db=db_session,
          username="testuser",
          email="test@example.com",
          password_hash="hashed_password"
      )
      assert user.id is not None
      assert user.username == "testuser"
      assert user.email == "test@example.com"
  ```
- **체크포인트**: 생성 테스트 완료

### 1.8.6 테스트 2: username 중복 에러
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: `backend/tests/test_user_crud.py`
- **작업**:
  ```python
  def test_create_user_duplicate_username(db_session):
      create_user(db_session, "testuser", "test1@example.com", "hash1")
      with pytest.raises(ValueError, match="already exists"):
          create_user(db_session, "testuser", "test2@example.com", "hash2")
  ```
- **체크포인트**: 중복 username 테스트 완료

### 1.8.7 테스트 3: email 중복 에러
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: `backend/tests/test_user_crud.py`
- **작업**:
  ```python
  def test_create_user_duplicate_email(db_session):
      create_user(db_session, "user1", "test@example.com", "hash1")
      with pytest.raises(ValueError, match="already exists"):
          create_user(db_session, "user2", "test@example.com", "hash2")
  ```
- **체크포인트**: 중복 email 테스트 완료

### 1.8.8 테스트 4: get_user_by_username 성공
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: `backend/tests/test_user_crud.py`
- **작업**:
  ```python
  def test_get_user_by_username_found(db_session):
      create_user(db_session, "testuser", "test@example.com", "hash")
      user = get_user_by_username(db_session, "testuser")
      assert user is not None
      assert user.username == "testuser"
  ```
- **체크포인트**: username 조회 테스트 완료

### 1.8.9 테스트 5: get_user_by_username 실패
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: `backend/tests/test_user_crud.py`
- **작업**:
  ```python
  def test_get_user_by_username_not_found(db_session):
      user = get_user_by_username(db_session, "nonexistent")
      assert user is None
  ```
- **체크포인트**: 존재하지 않는 사용자 테스트 완료

### 1.8.10 테스트 6: get_user_by_email 성공
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: `backend/tests/test_user_crud.py`
- **작업**:
  ```python
  def test_get_user_by_email_found(db_session):
      create_user(db_session, "testuser", "test@example.com", "hash")
      user = get_user_by_email(db_session, "test@example.com")
      assert user is not None
      assert user.email == "test@example.com"
  ```
- **체크포인트**: email 조회 테스트 완료

### 1.8.11 테스트 7: get_user_by_id 성공
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: `backend/tests/test_user_crud.py`
- **작업**:
  ```python
  def test_get_user_by_id_found(db_session):
      user = create_user(db_session, "testuser", "test@example.com", "hash")
      found_user = get_user_by_id(db_session, user.id)
      assert found_user is not None
      assert found_user.id == user.id
  ```
- **체크포인트**: id 조회 테스트 완료

### 1.8.12 테스트 8: 대소문자 구분 없는 조회
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: `backend/tests/test_user_crud.py`
- **작업**:
  ```python
  def test_case_insensitive_username(db_session):
      create_user(db_session, "TestUser", "test@example.com", "hash")
      user = get_user_by_username(db_session, "TESTUSER")
      assert user is not None
      assert user.username == "testuser"
  ```
- **체크포인트**: 대소문자 처리 테스트 완료

### 1.8.13 테스트 실행
- **담당**: `db-agent`
- **Skill**: `DB-test`
- **파일**: 없음 (명령어 실행)
- **작업**:
  ```bash
  cd backend
  pytest tests/test_user_crud.py -v
  ```
- **체크포인트**: 모든 테스트 통과 확인

---

# Phase 2: 백엔드 API 작업 (be-agent)

## 2.1 환경 준비

### 2.1.1 필요한 패키지 설치 확인
- **담당**: `be-agent`
- **파일**: `backend/requirements.txt`
- **작업**:
  - `python-jose[cryptography]` 확인/추가
  - `passlib[bcrypt]` 확인/추가
  - `python-multipart` 확인/추가
  - `python-dotenv` 확인/추가
- **체크포인트**: 패키지 확인 완료

### 2.1.2 .env 파일 생성
- **담당**: `be-agent`
- **파일**: `backend/.env` (새로 생성)
- **작업**:
  ```
  SECRET_KEY=your-secret-key-min-32-characters-long
  ALGORITHM=HS256
  ACCESS_TOKEN_EXPIRE_MINUTES=30
  ```
- **체크포인트**: 환경 변수 파일 생성 완료

### 2.1.3 .gitignore에 .env 추가
- **담당**: `be-agent`
- **파일**: `.gitignore`
- **작업**:
  - `.env` 라인 추가 (없으면)
- **체크포인트**: .env 파일 보안 완료

---

## 2.2 인증 유틸리티 구현

### 2.2.1 utils 디렉토리 생성
- **담당**: `be-agent`
- **파일**: `backend/app/utils/` (디렉토리)
- **작업**:
  - utils 디렉토리 생성
  - `__init__.py` 생성
- **체크포인트**: 디렉토리 준비 완료

### 2.2.2 auth.py 파일 생성 및 임포트
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/utils/auth.py` (새로 생성)
- **작업**:
  ```python
  from datetime import datetime, timedelta
  from typing import Optional
  from jose import JWTError, jwt
  from passlib.context import CryptContext
  import os
  from dotenv import load_dotenv

  load_dotenv()
  ```
- **체크포인트**: 파일 및 임포트 완료

### 2.2.3 비밀번호 해싱 - CryptContext 설정
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/utils/auth.py`
- **작업**:
  ```python
  pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
  ```
- **체크포인트**: bcrypt 컨텍스트 설정 완료

### 2.2.4 비밀번호 해싱 - hash_password 함수
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/utils/auth.py`
- **작업**:
  ```python
  def hash_password(password: str) -> str:
      """비밀번호를 해싱합니다."""
      return pwd_context.hash(password)
  ```
- **체크포인트**: 해싱 함수 완료

### 2.2.5 비밀번호 해싱 - verify_password 함수
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/utils/auth.py`
- **작업**:
  ```python
  def verify_password(plain_password: str, hashed_password: str) -> bool:
      """비밀번호를 검증합니다."""
      return pwd_context.verify(plain_password, hashed_password)
  ```
- **체크포인트**: 검증 함수 완료

### 2.2.6 JWT - 환경 변수 로드
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/utils/auth.py`
- **작업**:
  ```python
  SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key")
  ALGORITHM = os.getenv("ALGORITHM", "HS256")
  ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
  ```
- **체크포인트**: 환경 변수 설정 완료

### 2.2.7 JWT - create_access_token 함수 시그니처
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/utils/auth.py`
- **작업**:
  ```python
  def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
      """JWT 액세스 토큰을 생성합니다."""
      pass
  ```
- **체크포인트**: 함수 시그니처 완료

### 2.2.8 JWT - create_access_token 데이터 복사
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/utils/auth.py`
- **작업**:
  ```python
  to_encode = data.copy()
  ```
- **체크포인트**: 데이터 복사 완료

### 2.2.9 JWT - create_access_token 만료 시간 설정
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/utils/auth.py`
- **작업**:
  ```python
  if expires_delta:
      expire = datetime.utcnow() + expires_delta
  else:
      expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
  to_encode.update({"exp": expire})
  ```
- **체크포인트**: 만료 시간 로직 완료

### 2.2.10 JWT - create_access_token 토큰 생성
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/utils/auth.py`
- **작업**:
  ```python
  encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
  return encoded_jwt
  ```
- **체크포인트**: 토큰 생성 완료

### 2.2.11 JWT - decode_access_token 함수
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/utils/auth.py`
- **작업**:
  ```python
  def decode_access_token(token: str) -> Optional[dict]:
      """JWT 토큰을 디코딩합니다."""
      try:
          payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
          return payload
      except JWTError:
          return None
  ```
- **체크포인트**: 토큰 디코딩 함수 완료

---

## 2.3 Pydantic 스키마 정의

### 2.3.1 user.py 스키마 파일 생성
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/schemas/user.py` (수정 또는 생성)
- **작업**:
  ```python
  from pydantic import BaseModel, EmailStr, Field, validator
  from datetime import datetime
  import re
  ```
- **체크포인트**: 파일 준비 완료

### 2.3.2 UserCreate 스키마 - 기본 구조
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/schemas/user.py`
- **작업**:
  ```python
  class UserCreate(BaseModel):
      username: str = Field(..., min_length=3, max_length=50)
      email: EmailStr
      password: str = Field(..., min_length=8)
  ```
- **체크포인트**: 기본 필드 정의 완료

### 2.3.3 UserCreate 스키마 - username validator
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/schemas/user.py`
- **작업**:
  ```python
  @validator('username')
  def validate_username(cls, v):
      if not re.match(r'^[a-zA-Z0-9_]+$', v):
          raise ValueError('Username must contain only letters, numbers, and underscores')
      return v.lower()
  ```
- **체크포인트**: username 검증 완료

### 2.3.4 UserCreate 스키마 - password validator
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/schemas/user.py`
- **작업**:
  ```python
  @validator('password')
  def validate_password(cls, v):
      if not re.search(r'[A-Za-z]', v):
          raise ValueError('Password must contain at least one letter')
      if not re.search(r'[0-9]', v):
          raise ValueError('Password must contain at least one number')
      return v
  ```
- **체크포인트**: password 검증 완료

### 2.3.5 UserResponse 스키마
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/schemas/user.py`
- **작업**:
  ```python
  class UserResponse(BaseModel):
      id: int
      username: str
      email: str
      created_at: datetime

      class Config:
          from_attributes = True
  ```
- **체크포인트**: 응답 스키마 완료

### 2.3.6 auth.py 스키마 파일 생성
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/schemas/auth.py` (새로 생성)
- **작업**:
  ```python
  from pydantic import BaseModel, Field
  ```
- **체크포인트**: 파일 준비 완료

### 2.3.7 UserLogin 스키마
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/schemas/auth.py`
- **작업**:
  ```python
  class UserLogin(BaseModel):
      username_or_email: str = Field(..., min_length=3)
      password: str = Field(..., min_length=1)
  ```
- **체크포인트**: 로그인 스키마 완료

### 2.3.8 Token 스키마
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/schemas/auth.py`
- **작업**:
  ```python
  class Token(BaseModel):
      access_token: str
      token_type: str = "bearer"
  ```
- **체크포인트**: 토큰 스키마 완료

### 2.3.9 schemas/__init__.py 업데이트
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/schemas/__init__.py`
- **작업**:
  ```python
  from .user import UserCreate, UserResponse
  from .auth import UserLogin, Token
  ```
- **체크포인트**: 스키마 export 완료

---

## 2.4 인증 의존성 구현

### 2.4.1 dependencies 디렉토리 생성
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/dependencies/` (디렉토리)
- **작업**:
  - dependencies 디렉토리 생성
  - `__init__.py` 생성
- **체크포인트**: 디렉토리 준비 완료

### 2.4.2 auth.py 의존성 파일 생성 및 임포트
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/dependencies/auth.py` (새로 생성)
- **작업**:
  ```python
  from fastapi import Depends, HTTPException, status
  from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
  from sqlalchemy.orm import Session
  from app.database import get_db
  from app.utils.auth import decode_access_token
  from app.crud.user import get_user_by_id
  from app.models.user import User
  ```
- **체크포인트**: 임포트 완료

### 2.4.3 HTTPBearer 스키마 설정
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/dependencies/auth.py`
- **작업**:
  ```python
  security = HTTPBearer()
  ```
- **체크포인트**: 보안 스키마 설정 완료

### 2.4.4 get_current_user 함수 시그니처
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/dependencies/auth.py`
- **작업**:
  ```python
  async def get_current_user(
      credentials: HTTPAuthorizationCredentials = Depends(security),
      db: Session = Depends(get_db)
  ) -> User:
      """JWT 토큰에서 현재 사용자를 추출합니다."""
      pass
  ```
- **체크포인트**: 함수 시그니처 완료

### 2.4.5 get_current_user - 토큰 추출
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/dependencies/auth.py`
- **작업**:
  ```python
  token = credentials.credentials
  ```
- **체크포인트**: 토큰 추출 완료

### 2.4.6 get_current_user - 토큰 디코딩
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/dependencies/auth.py`
- **작업**:
  ```python
  payload = decode_access_token(token)
  if payload is None:
      raise HTTPException(
          status_code=status.HTTP_401_UNAUTHORIZED,
          detail="Could not validate credentials",
          headers={"WWW-Authenticate": "Bearer"},
      )
  ```
- **체크포인트**: 토큰 디코딩 및 검증 완료

### 2.4.7 get_current_user - user_id 추출
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/dependencies/auth.py`
- **작업**:
  ```python
  user_id: int = payload.get("sub")
  if user_id is None:
      raise HTTPException(
          status_code=status.HTTP_401_UNAUTHORIZED,
          detail="Could not validate credentials",
      )
  ```
- **체크포인트**: user_id 추출 완료

### 2.4.8 get_current_user - 사용자 조회
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/dependencies/auth.py`
- **작업**:
  ```python
  user = get_user_by_id(db, user_id=user_id)
  if user is None:
      raise HTTPException(
          status_code=status.HTTP_401_UNAUTHORIZED,
          detail="User not found",
      )
  return user
  ```
- **체크포인트**: 사용자 조회 및 반환 완료

---

## 2.5 API 엔드포인트 구현

### 2.5.1 auth.py 라우터 파일 생성 및 임포트
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py` (새로 생성)
- **작업**:
  ```python
  from fastapi import APIRouter, Depends, HTTPException, status
  from sqlalchemy.orm import Session
  from app.database import get_db
  from app.schemas.auth import UserLogin, Token
  from app.schemas.user import UserCreate, UserResponse
  from app.crud import user as user_crud
  from app.utils.auth import hash_password, verify_password, create_access_token
  from app.dependencies.auth import get_current_user
  from app.models.user import User
  ```
- **체크포인트**: 임포트 완료

### 2.5.2 APIRouter 생성
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  router = APIRouter(
      prefix="/api/auth",
      tags=["auth"]
  )
  ```
- **체크포인트**: 라우터 설정 완료

---

### 2.5.3 POST /register 엔드포인트 - 데코레이터
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  @router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
  async def register(
      user_data: UserCreate,
      db: Session = Depends(get_db)
  ):
      """새로운 사용자를 등록합니다."""
      pass
  ```
- **체크포인트**: 엔드포인트 시그니처 완료

### 2.5.4 POST /register - username 중복 확인
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  existing_user = user_crud.get_user_by_username(db, username=user_data.username)
  if existing_user:
      raise HTTPException(
          status_code=status.HTTP_400_BAD_REQUEST,
          detail="Username already registered"
      )
  ```
- **체크포인트**: username 중복 체크 완료

### 2.5.5 POST /register - email 중복 확인
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  existing_email = user_crud.get_user_by_email(db, email=user_data.email)
  if existing_email:
      raise HTTPException(
          status_code=status.HTTP_400_BAD_REQUEST,
          detail="Email already registered"
      )
  ```
- **체크포인트**: email 중복 체크 완료

### 2.5.6 POST /register - 비밀번호 해싱
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  hashed_password = hash_password(user_data.password)
  ```
- **체크포인트**: 비밀번호 해싱 완료

### 2.5.7 POST /register - 사용자 생성
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  try:
      new_user = user_crud.create_user(
          db=db,
          username=user_data.username,
          email=user_data.email,
          password_hash=hashed_password
      )
      return new_user
  except ValueError as e:
      raise HTTPException(
          status_code=status.HTTP_400_BAD_REQUEST,
          detail=str(e)
      )
  ```
- **체크포인트**: 사용자 생성 및 반환 완료

---

### 2.5.8 POST /login 엔드포인트 - 데코레이터
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  @router.post("/login", response_model=Token)
  async def login(
      login_data: UserLogin,
      db: Session = Depends(get_db)
  ):
      """사용자 로그인을 처리합니다."""
      pass
  ```
- **체크포인트**: 엔드포인트 시그니처 완료

### 2.5.9 POST /login - 사용자 조회 (username 또는 email)
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  user = user_crud.get_user_by_username(db, username=login_data.username_or_email)
  if not user:
      user = user_crud.get_user_by_email(db, email=login_data.username_or_email)
  ```
- **체크포인트**: 사용자 조회 로직 완료

### 2.5.10 POST /login - 사용자 존재 여부 확인
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  if not user:
      raise HTTPException(
          status_code=status.HTTP_401_UNAUTHORIZED,
          detail="Incorrect username or password"
      )
  ```
- **체크포인트**: 사용자 존재 확인 완료

### 2.5.11 POST /login - 비밀번호 검증
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  if not verify_password(login_data.password, user.password_hash):
      raise HTTPException(
          status_code=status.HTTP_401_UNAUTHORIZED,
          detail="Incorrect username or password"
      )
  ```
- **체크포인트**: 비밀번호 검증 완료

### 2.5.12 POST /login - JWT 토큰 생성
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  access_token = create_access_token(data={"sub": user.id})
  ```
- **체크포인트**: 토큰 생성 완료

### 2.5.13 POST /login - 토큰 반환
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  return {
      "access_token": access_token,
      "token_type": "bearer"
  }
  ```
- **체크포인트**: 토큰 반환 완료

---

### 2.5.14 GET /me 엔드포인트 - 데코레이터
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/routers/auth.py`
- **작업**:
  ```python
  @router.get("/me", response_model=UserResponse)
  async def get_me(
      current_user: User = Depends(get_current_user)
  ):
      """현재 로그인한 사용자 정보를 조회합니다."""
      return current_user
  ```
- **체크포인트**: /me 엔드포인트 완료

---

### 2.5.15 main.py에 라우터 등록
- **담당**: `be-agent`
- **Skill**: `BE-endpoint`
- **파일**: `backend/app/main.py`
- **작업**:
  ```python
  from app.routers import auth

  app.include_router(auth.router)
  ```
- **체크포인트**: 라우터 등록 완료

---

## 2.6 백엔드 API 테스트 작성

### 2.6.1 test_auth_api.py 파일 생성 및 임포트
- **담당**: `be-agent`
- **Skill**: `BE-test`
- **파일**: `backend/tests/test_auth_api.py` (새로 생성)
- **작업**:
  ```python
  import pytest
  from fastapi.testclient import TestClient
  from app.main import app

  client = TestClient(app)
  ```
- **체크포인트**: 테스트 클라이언트 준비 완료

### 2.6.2 테스트 1: 회원가입 성공
- **담당**: `be-agent`
- **Skill**: `BE-test`
- **파일**: `backend/tests/test_auth_api.py`
- **작업**:
  ```python
  def test_register_success():
      response = client.post("/api/auth/register", json={
          "username": "testuser",
          "email": "test@example.com",
          "password": "password123"
      })
      assert response.status_code == 201
      data = response.json()
      assert data["username"] == "testuser"
      assert data["email"] == "test@example.com"
      assert "id" in data
  ```
- **체크포인트**: 회원가입 성공 테스트 완료

### 2.6.3 테스트 2: 회원가입 실패 - 중복 username
- **담당**: `be-agent`
- **Skill**: `BE-test`
- **파일**: `backend/tests/test_auth_api.py`
- **작업**:
  ```python
  def test_register_duplicate_username():
      client.post("/api/auth/register", json={
          "username": "duplicate",
          "email": "test1@example.com",
          "password": "password123"
      })
      response = client.post("/api/auth/register", json={
          "username": "duplicate",
          "email": "test2@example.com",
          "password": "password123"
      })
      assert response.status_code == 400
      assert "already registered" in response.json()["detail"].lower()
  ```
- **체크포인트**: 중복 username 테스트 완료

### 2.6.4 테스트 3: 회원가입 실패 - 약한 비밀번호
- **담당**: `be-agent`
- **Skill**: `BE-test`
- **파일**: `backend/tests/test_auth_api.py`
- **작업**:
  ```python
  def test_register_weak_password():
      response = client.post("/api/auth/register", json={
          "username": "testuser2",
          "email": "test2@example.com",
          "password": "12345678"  # 숫자만
      })
      assert response.status_code == 422
  ```
- **체크포인트**: 약한 비밀번호 테스트 완료

### 2.6.5 테스트 4: 로그인 성공 (username)
- **담당**: `be-agent`
- **Skill**: `BE-test`
- **파일**: `backend/tests/test_auth_api.py`
- **작업**:
  ```python
  def test_login_success_with_username():
      # 먼저 회원가입
      client.post("/api/auth/register", json={
          "username": "loginuser",
          "email": "login@example.com",
          "password": "password123"
      })
      # 로그인
      response = client.post("/api/auth/login", json={
          "username_or_email": "loginuser",
          "password": "password123"
      })
      assert response.status_code == 200
      data = response.json()
      assert "access_token" in data
      assert data["token_type"] == "bearer"
  ```
- **체크포인트**: username 로그인 테스트 완료

### 2.6.6 테스트 5: 로그인 성공 (email)
- **담당**: `be-agent`
- **Skill**: `BE-test`
- **파일**: `backend/tests/test_auth_api.py`
- **작업**:
  ```python
  def test_login_success_with_email():
      response = client.post("/api/auth/login", json={
          "username_or_email": "login@example.com",
          "password": "password123"
      })
      assert response.status_code == 200
  ```
- **체크포인트**: email 로그인 테스트 완료

### 2.6.7 테스트 6: 로그인 실패 - 잘못된 비밀번호
- **담당**: `be-agent`
- **Skill**: `BE-test`
- **파일**: `backend/tests/test_auth_api.py`
- **작업**:
  ```python
  def test_login_wrong_password():
      response = client.post("/api/auth/login", json={
          "username_or_email": "loginuser",
          "password": "wrongpassword"
      })
      assert response.status_code == 401
  ```
- **체크포인트**: 잘못된 비밀번호 테스트 완료

### 2.6.8 테스트 7: 로그인 실패 - 존재하지 않는 사용자
- **담당**: `be-agent`
- **Skill**: `BE-test`
- **파일**: `backend/tests/test_auth_api.py`
- **작업**:
  ```python
  def test_login_user_not_found():
      response = client.post("/api/auth/login", json={
          "username_or_email": "nonexistent",
          "password": "password123"
      })
      assert response.status_code == 401
  ```
- **체크포인트**: 존재하지 않는 사용자 테스트 완료

### 2.6.9 테스트 8: /me 성공
- **담당**: `be-agent`
- **Skill**: `BE-test`
- **파일**: `backend/tests/test_auth_api.py`
- **작업**:
  ```python
  def test_get_me_success():
      # 로그인해서 토큰 받기
      login_response = client.post("/api/auth/login", json={
          "username_or_email": "loginuser",
          "password": "password123"
      })
      token = login_response.json()["access_token"]

      # /me 호출
      response = client.get("/api/auth/me", headers={
          "Authorization": f"Bearer {token}"
      })
      assert response.status_code == 200
      data = response.json()
      assert data["username"] == "loginuser"
  ```
- **체크포인트**: /me 성공 테스트 완료

### 2.6.10 테스트 9: /me 실패 - 토큰 없음
- **담당**: `be-agent`
- **Skill**: `BE-test`
- **파일**: `backend/tests/test_auth_api.py`
- **작업**:
  ```python
  def test_get_me_no_token():
      response = client.get("/api/auth/me")
      assert response.status_code == 403  # HTTPBearer는 403 반환
  ```
- **체크포인트**: 토큰 없음 테스트 완료

### 2.6.11 테스트 10: /me 실패 - 유효하지 않은 토큰
- **담당**: `be-agent`
- **Skill**: `BE-test`
- **파일**: `backend/tests/test_auth_api.py`
- **작업**:
  ```python
  def test_get_me_invalid_token():
      response = client.get("/api/auth/me", headers={
          "Authorization": "Bearer invalid_token"
      })
      assert response.status_code == 401
  ```
- **체크포인트**: 유효하지 않은 토큰 테스트 완료

### 2.6.12 테스트 실행
- **담당**: `be-agent`
- **Skill**: `BE-test`
- **파일**: 없음 (명령어 실행)
- **작업**:
  ```bash
  cd backend
  pytest tests/test_auth_api.py -v
  ```
- **체크포인트**: 모든 API 테스트 통과 확인

---

# Phase 3: 프론트엔드 작업 (fe-agent)

## 3.1 환경 준비

### 3.1.1 필요한 패키지 설치 확인
- **담당**: `fe-agent`
- **파일**: `frontend/package.json`
- **작업**:
  - React, Next.js 설치 확인
  - TypeScript 확인
  - Tailwind CSS 확인
- **체크포인트**: 기본 패키지 확인 완료

### 3.1.2 디렉토리 구조 확인
- **담당**: `fe-agent`
- **파일**: `frontend/src/`
- **작업**:
  - `app/` 디렉토리 확인
  - `components/` 디렉토리 확인 (없으면 생성)
  - `lib/` 디렉토리 확인 (없으면 생성)
  - `contexts/` 디렉토리 확인 (없으면 생성)
- **체크포인트**: 디렉토리 구조 준비 완료

---

## 3.2 타입 정의

### 3.2.1 types 디렉토리 생성
- **담당**: `fe-agent`
- **Skill**: `FE-refactor`
- **파일**: `frontend/src/types/` (디렉토리)
- **작업**:
  - types 디렉토리 생성
- **체크포인트**: 디렉토리 생성 완료

### 3.2.2 auth.ts 타입 파일 생성
- **담당**: `fe-agent`
- **Skill**: `FE-refactor`
- **파일**: `frontend/src/types/auth.ts` (새로 생성)
- **작업**:
  ```typescript
  export interface User {
    id: number
    username: string
    email: string
    created_at: string
  }
  ```
- **체크포인트**: User 타입 완료

### 3.2.3 RegisterData 타입 정의
- **담당**: `fe-agent`
- **Skill**: `FE-refactor`
- **파일**: `frontend/src/types/auth.ts`
- **작업**:
  ```typescript
  export interface RegisterData {
    username: string
    email: string
    password: string
  }
  ```
- **체크포인트**: RegisterData 타입 완료

### 3.2.4 LoginData 타입 정의
- **담당**: `fe-agent`
- **Skill**: `FE-refactor`
- **파일**: `frontend/src/types/auth.ts`
- **작업**:
  ```typescript
  export interface LoginData {
    username_or_email: string
    password: string
  }
  ```
- **체크포인트**: LoginData 타입 완료

### 3.2.5 Token 타입 정의
- **담당**: `fe-agent`
- **Skill**: `FE-refactor`
- **파일**: `frontend/src/types/auth.ts`
- **작업**:
  ```typescript
  export interface Token {
    access_token: string
    token_type: string
  }
  ```
- **체크포인트**: Token 타입 완료

---

## 3.3 API 연동 함수

### 3.3.1 lib/api 디렉토리 생성
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/lib/api/` (디렉토리)
- **작업**:
  - lib/api 디렉토리 생성
- **체크포인트**: 디렉토리 생성 완료

### 3.3.2 auth.ts API 파일 생성 및 임포트
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/lib/api/auth.ts` (새로 생성)
- **작업**:
  ```typescript
  import type { User, RegisterData, LoginData, Token } from '@/types/auth'

  const API_BASE = process.env.NEXT_PUBLIC_API_URL || ''
  ```
- **체크포인트**: 파일 및 임포트 완료

### 3.3.3 register 함수 - 시그니처
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/lib/api/auth.ts`
- **작업**:
  ```typescript
  export async function register(data: RegisterData): Promise<User> {
    // 구현 예정
  }
  ```
- **체크포인트**: 함수 시그니처 완료

### 3.3.4 register 함수 - fetch 호출
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/lib/api/auth.ts`
- **작업**:
  ```typescript
  const response = await fetch(`${API_BASE}/api/auth/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  })
  ```
- **체크포인트**: fetch 호출 완료

### 3.3.5 register 함수 - 에러 처리
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/lib/api/auth.ts`
- **작업**:
  ```typescript
  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.detail || 'Registration failed')
  }
  ```
- **체크포인트**: 에러 처리 완료

### 3.3.6 register 함수 - 응답 반환
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/lib/api/auth.ts`
- **작업**:
  ```typescript
  return await response.json()
  ```
- **체크포인트**: register 함수 완료

### 3.3.7 login 함수 - 시그니처
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/lib/api/auth.ts`
- **작업**:
  ```typescript
  export async function login(data: LoginData): Promise<Token> {
    // 구현 예정
  }
  ```
- **체크포인트**: 함수 시그니처 완료

### 3.3.8 login 함수 - fetch 호출
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/lib/api/auth.ts`
- **작업**:
  ```typescript
  const response = await fetch(`${API_BASE}/api/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  })
  ```
- **체크포인트**: fetch 호출 완료

### 3.3.9 login 함수 - 에러 처리 및 반환
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/lib/api/auth.ts`
- **작업**:
  ```typescript
  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.detail || 'Login failed')
  }
  return await response.json()
  ```
- **체크포인트**: login 함수 완료

### 3.3.10 getCurrentUser 함수 - 시그니처
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/lib/api/auth.ts`
- **작업**:
  ```typescript
  export async function getCurrentUser(token: string): Promise<User> {
    // 구현 예정
  }
  ```
- **체크포인트**: 함수 시그니처 완료

### 3.3.11 getCurrentUser 함수 - fetch 호출 (Authorization 헤더)
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/lib/api/auth.ts`
- **작업**:
  ```typescript
  const response = await fetch(`${API_BASE}/api/auth/me`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  })
  ```
- **체크포인트**: Authorization 헤더 포함 fetch 완료

### 3.3.12 getCurrentUser 함수 - 에러 처리 및 반환
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/lib/api/auth.ts`
- **작업**:
  ```typescript
  if (!response.ok) {
    throw new Error('Failed to fetch user')
  }
  return await response.json()
  ```
- **체크포인트**: getCurrentUser 함수 완료

---

## 3.4 인증 Context 구현

### 3.4.1 AuthContext.tsx 파일 생성 및 임포트
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/contexts/AuthContext.tsx` (새로 생성)
- **작업**:
  ```typescript
  'use client'

  import React, { createContext, useContext, useState, useEffect } from 'react'
  import type { User, RegisterData } from '@/types/auth'
  import * as authApi from '@/lib/api/auth'
  ```
- **체크포인트**: 파일 및 임포트 완료

### 3.4.2 AuthContextType 인터페이스 정의
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/contexts/AuthContext.tsx`
- **작업**:
  ```typescript
  interface AuthContextType {
    user: User | null
    token: string | null
    isAuthenticated: boolean
    login: (username: string, password: string) => Promise<void>
    register: (data: RegisterData) => Promise<void>
    logout: () => void
    isLoading: boolean
  }
  ```
- **체크포인트**: Context 타입 정의 완료

### 3.4.3 AuthContext 생성
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/contexts/AuthContext.tsx`
- **작업**:
  ```typescript
  const AuthContext = createContext<AuthContextType | undefined>(undefined)
  ```
- **체크포인트**: Context 생성 완료

### 3.4.4 AuthProvider 컴포넌트 - 시그니처 및 state
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/contexts/AuthContext.tsx`
- **작업**:
  ```typescript
  export function AuthProvider({ children }: { children: React.ReactNode }) {
    const [user, setUser] = useState<User | null>(null)
    const [token, setToken] = useState<string | null>(null)
    const [isLoading, setIsLoading] = useState(true)
  ```
- **체크포인트**: state 정의 완료

### 3.4.5 AuthProvider - useEffect (토큰 복원)
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/contexts/AuthContext.tsx`
- **작업**:
  ```typescript
  useEffect(() => {
    const storedToken = localStorage.getItem('access_token')
    if (storedToken) {
      authApi.getCurrentUser(storedToken)
        .then(user => {
          setUser(user)
          setToken(storedToken)
        })
        .catch(() => {
          localStorage.removeItem('access_token')
        })
        .finally(() => setIsLoading(false))
    } else {
      setIsLoading(false)
    }
  }, [])
  ```
- **체크포인트**: 토큰 복원 로직 완료

### 3.4.6 AuthProvider - login 함수
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/contexts/AuthContext.tsx`
- **작업**:
  ```typescript
  const login = async (username: string, password: string) => {
    const tokenData = await authApi.login({
      username_or_email: username,
      password,
    })

    localStorage.setItem('access_token', tokenData.access_token)
    setToken(tokenData.access_token)

    const userData = await authApi.getCurrentUser(tokenData.access_token)
    setUser(userData)
  }
  ```
- **체크포인트**: login 함수 완료

### 3.4.7 AuthProvider - register 함수
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/contexts/AuthContext.tsx`
- **작업**:
  ```typescript
  const register = async (data: RegisterData) => {
    const newUser = await authApi.register(data)
    // 회원가입 후 자동 로그인
    await login(data.username, data.password)
  }
  ```
- **체크포인트**: register 함수 완료

### 3.4.8 AuthProvider - logout 함수
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/contexts/AuthContext.tsx`
- **작업**:
  ```typescript
  const logout = () => {
    localStorage.removeItem('access_token')
    setUser(null)
    setToken(null)
  }
  ```
- **체크포인트**: logout 함수 완료

### 3.4.9 AuthProvider - value 정의 및 Provider 반환
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/contexts/AuthContext.tsx`
- **작업**:
  ```typescript
  const value = {
    user,
    token,
    isAuthenticated: !!user,
    login,
    register,
    logout,
    isLoading,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
  }
  ```
- **체크포인트**: Provider 완료

### 3.4.10 useAuth hook 구현
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/contexts/AuthContext.tsx`
- **작업**:
  ```typescript
  export function useAuth() {
    const context = useContext(AuthContext)
    if (context === undefined) {
      throw new Error('useAuth must be used within an AuthProvider')
    }
    return context
  }
  ```
- **체크포인트**: useAuth hook 완료

### 3.4.11 layout.tsx에 AuthProvider 추가
- **담당**: `fe-agent`
- **Skill**: `FE-api`
- **파일**: `frontend/src/app/layout.tsx`
- **작업**:
  ```typescript
  import { AuthProvider } from '@/contexts/AuthContext'

  // RootLayout 컴포넌트 내부의 body 태그 안에
  <AuthProvider>
    {children}
  </AuthProvider>
  ```
- **체크포인트**: AuthProvider 등록 완료

---

## 3.5 로그인 페이지 구현

### 3.5.1 login 디렉토리 생성
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/login/` (디렉토리)
- **작업**:
  - login 디렉토리 생성
- **체크포인트**: 디렉토리 생성 완료

### 3.5.2 page.tsx 파일 생성 및 임포트
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/login/page.tsx` (새로 생성)
- **작업**:
  ```typescript
  'use client'

  import { useState } from 'react'
  import { useRouter } from 'next/navigation'
  import Link from 'next/link'
  import { useAuth } from '@/contexts/AuthContext'
  ```
- **체크포인트**: 임포트 완료

### 3.5.3 LoginPage 컴포넌트 - 시그니처 및 state
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/login/page.tsx`
- **작업**:
  ```typescript
  export default function LoginPage() {
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [error, setError] = useState('')
    const [isLoading, setIsLoading] = useState(false)

    const { login } = useAuth()
    const router = useRouter()
  ```
- **체크포인트**: state 정의 완료

### 3.5.4 LoginPage - handleSubmit 함수
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/login/page.tsx`
- **작업**:
  ```typescript
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    try {
      await login(username, password)
      router.push('/')  // 로그인 후 홈으로 이동
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setIsLoading(false)
    }
  }
  ```
- **체크포인트**: handleSubmit 함수 완료

### 3.5.5 LoginPage - JSX 구조 (컨테이너)
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/login/page.tsx`
- **작업**:
  ```typescript
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="max-w-md w-full bg-white rounded-lg shadow-md p-8">
        <h1 className="text-2xl font-bold text-center mb-6">로그인</h1>
        {/* 폼 내용 */}
      </div>
    </div>
  )
  ```
- **체크포인트**: 컨테이너 구조 완료

### 3.5.6 LoginPage - 에러 메시지 표시
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/login/page.tsx`
- **작업**:
  ```typescript
  {error && (
    <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
      {error}
    </div>
  )}
  ```
- **체크포인트**: 에러 메시지 UI 완료

### 3.5.7 LoginPage - form 태그
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/login/page.tsx`
- **작업**:
  ```typescript
  <form onSubmit={handleSubmit} className="space-y-4">
    {/* 폼 필드 */}
  </form>
  ```
- **체크포인트**: form 태그 완료

### 3.5.8 LoginPage - username 입력 필드
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/login/page.tsx`
- **작업**:
  ```typescript
  <div>
    <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
      사용자명 또는 이메일
    </label>
    <input
      type="text"
      id="username"
      value={username}
      onChange={(e) => setUsername(e.target.value)}
      required
      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
      placeholder="username 또는 email"
    />
  </div>
  ```
- **체크포인트**: username 필드 완료

### 3.5.9 LoginPage - password 입력 필드
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/login/page.tsx`
- **작업**:
  ```typescript
  <div>
    <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
      비밀번호
    </label>
    <input
      type="password"
      id="password"
      value={password}
      onChange={(e) => setPassword(e.target.value)}
      required
      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
      placeholder="비밀번호"
    />
  </div>
  ```
- **체크포인트**: password 필드 완료

### 3.5.10 LoginPage - 로그인 버튼
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/login/page.tsx`
- **작업**:
  ```typescript
  <button
    type="submit"
    disabled={isLoading}
    className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:bg-blue-300 disabled:cursor-not-allowed transition"
  >
    {isLoading ? '로그인 중...' : '로그인'}
  </button>
  ```
- **체크포인트**: 로그인 버튼 완료

### 3.5.11 LoginPage - 회원가입 링크
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/login/page.tsx`
- **작업**:
  ```typescript
  <p className="text-center text-sm text-gray-600 mt-4">
    계정이 없으신가요?{' '}
    <Link href="/register" className="text-blue-600 hover:underline">
      회원가입
    </Link>
  </p>
  ```
- **체크포인트**: 회원가입 링크 완료

---

## 3.6 회원가입 페이지 구현

### 3.6.1 register 디렉토리 생성
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/register/` (디렉토리)
- **작업**:
  - register 디렉토리 생성
- **체크포인트**: 디렉토리 생성 완료

### 3.6.2 page.tsx 파일 생성 및 임포트
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/register/page.tsx` (새로 생성)
- **작업**:
  ```typescript
  'use client'

  import { useState } from 'react'
  import { useRouter } from 'next/navigation'
  import Link from 'next/link'
  import { useAuth } from '@/contexts/AuthContext'
  ```
- **체크포인트**: 임포트 완료

### 3.6.3 RegisterPage 컴포넌트 - state
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/register/page.tsx`
- **작업**:
  ```typescript
  export default function RegisterPage() {
    const [username, setUsername] = useState('')
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [confirmPassword, setConfirmPassword] = useState('')
    const [error, setError] = useState('')
    const [isLoading, setIsLoading] = useState(false)

    const { register } = useAuth()
    const router = useRouter()
  ```
- **체크포인트**: state 정의 완료

### 3.6.4 RegisterPage - handleSubmit 함수 (유효성 검사)
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/register/page.tsx`
- **작업**:
  ```typescript
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    // 비밀번호 확인
    if (password !== confirmPassword) {
      setError('비밀번호가 일치하지 않습니다')
      return
    }

    // 비밀번호 강도 검사
    if (password.length < 8) {
      setError('비밀번호는 최소 8자 이상이어야 합니다')
      return
    }
    if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      setError('비밀번호는 영문과 숫자를 포함해야 합니다')
      return
    }

    setIsLoading(true)

    try {
      await register({ username, email, password })
      router.push('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed')
    } finally {
      setIsLoading(false)
    }
  }
  ```
- **체크포인트**: handleSubmit 함수 완료

### 3.6.5 RegisterPage - JSX 구조 (컨테이너 및 제목)
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/register/page.tsx`
- **작업**:
  ```typescript
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="max-w-md w-full bg-white rounded-lg shadow-md p-8">
        <h1 className="text-2xl font-bold text-center mb-6">회원가입</h1>
        {/* 폼 내용 */}
      </div>
    </div>
  )
  ```
- **체크포인트**: 컨테이너 구조 완료

### 3.6.6 RegisterPage - 에러 메시지 표시
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/register/page.tsx`
- **작업**:
  ```typescript
  {error && (
    <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
      {error}
    </div>
  )}
  ```
- **체크포인트**: 에러 메시지 UI 완료

### 3.6.7 RegisterPage - form 및 username 필드
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/register/page.tsx`
- **작업**:
  ```typescript
  <form onSubmit={handleSubmit} className="space-y-4">
    <div>
      <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
        사용자명
      </label>
      <input
        type="text"
        id="username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        required
        minLength={3}
        maxLength={50}
        pattern="[a-zA-Z0-9_]+"
        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        placeholder="영문, 숫자, 언더스코어만 사용"
      />
    </div>
  ```
- **체크포인트**: username 필드 완료

### 3.6.8 RegisterPage - email 필드
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/register/page.tsx`
- **작업**:
  ```typescript
  <div>
    <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
      이메일
    </label>
    <input
      type="email"
      id="email"
      value={email}
      onChange={(e) => setEmail(e.target.value)}
      required
      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
      placeholder="example@email.com"
    />
  </div>
  ```
- **체크포인트**: email 필드 완료

### 3.6.9 RegisterPage - password 필드
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/register/page.tsx`
- **작업**:
  ```typescript
  <div>
    <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
      비밀번호
    </label>
    <input
      type="password"
      id="password"
      value={password}
      onChange={(e) => setPassword(e.target.value)}
      required
      minLength={8}
      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
      placeholder="최소 8자, 영문+숫자 조합"
    />
  </div>
  ```
- **체크포인트**: password 필드 완료

### 3.6.10 RegisterPage - confirmPassword 필드
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/register/page.tsx`
- **작업**:
  ```typescript
  <div>
    <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-1">
      비밀번호 확인
    </label>
    <input
      type="password"
      id="confirmPassword"
      value={confirmPassword}
      onChange={(e) => setConfirmPassword(e.target.value)}
      required
      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
      placeholder="비밀번호 재입력"
    />
  </div>
  ```
- **체크포인트**: confirmPassword 필드 완료

### 3.6.11 RegisterPage - 회원가입 버튼
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/register/page.tsx`
- **작업**:
  ```typescript
  <button
    type="submit"
    disabled={isLoading}
    className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:bg-blue-300 disabled:cursor-not-allowed transition"
  >
    {isLoading ? '가입 중...' : '회원가입'}
  </button>
  </form>
  ```
- **체크포인트**: 회원가입 버튼 완료

### 3.6.12 RegisterPage - 로그인 링크
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/register/page.tsx`
- **작업**:
  ```typescript
  <p className="text-center text-sm text-gray-600 mt-4">
    이미 계정이 있으신가요?{' '}
    <Link href="/login" className="text-blue-600 hover:underline">
      로그인
    </Link>
  </p>
  ```
- **체크포인트**: 로그인 링크 완료

---

## 3.7 네비게이션 컴포넌트

### 3.7.1 Navbar 컴포넌트 파일 생성
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/components/Navbar.tsx` (새로 생성)
- **작업**:
  ```typescript
  'use client'

  import Link from 'next/link'
  import { useAuth } from '@/contexts/AuthContext'
  ```
- **체크포인트**: 파일 및 임포트 완료

### 3.7.2 Navbar 컴포넌트 - 구조
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/components/Navbar.tsx`
- **작업**:
  ```typescript
  export default function Navbar() {
    const { user, isAuthenticated, logout } = useAuth()

    return (
      <nav className="bg-white shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            {/* 로고 */}
            {/* 메뉴 */}
          </div>
        </div>
      </nav>
    )
  }
  ```
- **체크포인트**: 기본 구조 완료

### 3.7.3 Navbar - 로고 영역
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/components/Navbar.tsx`
- **작업**:
  ```typescript
  <div className="flex items-center">
    <Link href="/" className="text-xl font-bold text-blue-600">
      MyApp
    </Link>
  </div>
  ```
- **체크포인트**: 로고 완료

### 3.7.4 Navbar - 메뉴 영역 (미인증)
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/components/Navbar.tsx`
- **작업**:
  ```typescript
  <div className="flex items-center space-x-4">
    {!isAuthenticated ? (
      <>
        <Link
          href="/login"
          className="text-gray-700 hover:text-blue-600 px-3 py-2 rounded-md text-sm font-medium"
        >
          로그인
        </Link>
        <Link
          href="/register"
          className="bg-blue-600 text-white hover:bg-blue-700 px-4 py-2 rounded-md text-sm font-medium"
        >
          회원가입
        </Link>
      </>
    ) : (
      {/* 인증된 사용자 메뉴 */}
    )}
  </div>
  ```
- **체크포인트**: 미인증 메뉴 완료

### 3.7.5 Navbar - 메뉴 영역 (인증됨)
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/components/Navbar.tsx`
- **작업**:
  ```typescript
  <>
    <span className="text-gray-700 text-sm">
      환영합니다, <span className="font-semibold">{user?.username}</span>님
    </span>
    <button
      onClick={logout}
      className="bg-red-600 text-white hover:bg-red-700 px-4 py-2 rounded-md text-sm font-medium"
    >
      로그아웃
    </button>
  </>
  ```
- **체크포인트**: 인증된 메뉴 완료

### 3.7.6 layout.tsx에 Navbar 추가
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/layout.tsx`
- **작업**:
  ```typescript
  import Navbar from '@/components/Navbar'

  // AuthProvider 안에
  <>
    <Navbar />
    {children}
  </>
  ```
- **체크포인트**: Navbar 등록 완료

---

## 3.8 인증 보호 컴포넌트

### 3.8.1 ProtectedRoute 컴포넌트 생성
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/components/ProtectedRoute.tsx` (새로 생성)
- **작업**:
  ```typescript
  'use client'

  import { useEffect } from 'react'
  import { useRouter } from 'next/navigation'
  import { useAuth } from '@/contexts/AuthContext'
  ```
- **체크포인트**: 임포트 완료

### 3.8.2 ProtectedRoute - 컴포넌트 로직
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/components/ProtectedRoute.tsx`
- **작업**:
  ```typescript
  export default function ProtectedRoute({ children }: { children: React.ReactNode }) {
    const { isAuthenticated, isLoading } = useAuth()
    const router = useRouter()

    useEffect(() => {
      if (!isLoading && !isAuthenticated) {
        router.push('/login')
      }
    }, [isAuthenticated, isLoading, router])

    if (isLoading) {
      return (
        <div className="min-h-screen flex items-center justify-center">
          <div className="text-gray-600">로딩 중...</div>
        </div>
      )
    }

    if (!isAuthenticated) {
      return null
    }

    return <>{children}</>
  }
  ```
- **체크포인트**: ProtectedRoute 완료

---

## 3.9 홈페이지 업데이트 (인증 상태 표시)

### 3.9.1 page.tsx 수정 - 인증 상태 표시
- **담당**: `fe-agent`
- **Skill**: `FE-page`
- **파일**: `frontend/src/app/page.tsx`
- **작업**:
  ```typescript
  'use client'

  import { useAuth } from '@/contexts/AuthContext'

  export default function Home() {
    const { user, isAuthenticated } = useAuth()

    return (
      <main className="min-h-screen p-8">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-4xl font-bold mb-4">홈페이지</h1>
          {isAuthenticated ? (
            <div>
              <p className="text-lg">환영합니다, {user?.username}님!</p>
              <p className="text-gray-600 mt-2">이메일: {user?.email}</p>
            </div>
          ) : (
            <p className="text-gray-600">로그인하여 더 많은 기능을 이용하세요.</p>
          )}
        </div>
      </main>
    )
  }
  ```
- **체크포인트**: 홈페이지 인증 상태 표시 완료

---

## 3.10 프론트엔드 테스트 작성 (Optional)

### 3.10.1 테스트 라이브러리 설치
- **담당**: `fe-agent`
- **Skill**: `FE-test`
- **파일**: 없음 (명령어)
- **작업**:
  ```bash
  cd frontend
  npm install --save-dev @testing-library/react @testing-library/jest-dom jest jest-environment-jsdom
  ```
- **체크포인트**: 테스트 라이브러리 설치 완료

### 3.10.2 jest.config.js 생성
- **담당**: `fe-agent`
- **Skill**: `FE-test`
- **파일**: `frontend/jest.config.js`
- **작업**: Jest 설정 파일 생성
- **체크포인트**: Jest 설정 완료

### 3.10.3 LoginPage 테스트 작성
- **담당**: `fe-agent`
- **Skill**: `FE-test`
- **파일**: `frontend/src/app/login/__tests__/page.test.tsx`
- **작업**: 로그인 페이지 렌더링 및 폼 제출 테스트
- **체크포인트**: 로그인 테스트 완료

### 3.10.4 RegisterPage 테스트 작성
- **담당**: `fe-agent`
- **Skill**: `FE-test`
- **파일**: `frontend/src/app/register/__tests__/page.test.tsx`
- **작업**: 회원가입 페이지 렌더링 및 유효성 검사 테스트
- **체크포인트**: 회원가입 테스트 완료

---

# 최종 검증 및 통합 테스트

## 4.1 백엔드 서버 실행 및 테스트

### 4.1.1 백엔드 서버 실행
- **담당**: 메인 에이전트
- **작업**:
  ```bash
  cd backend
  .venv\Scripts\activate
  uvicorn app.main:app --reload
  ```
- **체크포인트**: 서버가 http://localhost:8000 에서 실행됨

### 4.1.2 Swagger UI 확인
- **담당**: 메인 에이전트
- **작업**: 브라우저에서 http://localhost:8000/docs 접속
- **체크포인트**: API 문서 정상 표시, 3개 엔드포인트 확인

### 4.1.3 Swagger에서 API 테스트
- **담당**: 메인 에이전트
- **작업**:
  1. POST /api/auth/register 테스트
  2. POST /api/auth/login 테스트
  3. GET /api/auth/me 테스트 (토큰 사용)
- **체크포인트**: 모든 API가 정상 동작

---

## 4.2 프론트엔드 서버 실행 및 테스트

### 4.2.1 프론트엔드 서버 실행
- **담당**: 메인 에이전트
- **작업**:
  ```bash
  cd frontend
  npm run dev
  ```
- **체크포인트**: 서버가 http://localhost:3000 에서 실행됨

### 4.2.2 홈페이지 확인
- **담당**: 메인 에이전트
- **작업**: 브라우저에서 http://localhost:3000 접속
- **체크포인트**: 홈페이지 렌더링, Navbar 표시

### 4.2.3 회원가입 플로우 테스트
- **담당**: 메인 에이전트
- **작업**:
  1. "회원가입" 버튼 클릭
  2. 폼 작성 및 제출
  3. 자동 로그인 확인
  4. 홈페이지 리다이렉트 확인
- **체크포인트**: 회원가입 → 로그인 → 홈 플로우 정상 동작

### 4.2.4 로그아웃 테스트
- **담당**: 메인 에이전트
- **작업**:
  1. "로그아웃" 버튼 클릭
  2. 로그인 상태 해제 확인
  3. Navbar 변경 확인
- **체크포인트**: 로그아웃 정상 동작

### 4.2.5 로그인 플로우 테스트
- **담당**: 메인 에이전트
- **작업**:
  1. "로그인" 버튼 클릭
  2. 폼 작성 및 제출
  3. 홈페이지 리다이렉트 확인
- **체크포인트**: 로그인 플로우 정상 동작

### 4.2.6 토큰 유지 테스트
- **담당**: 메인 에이전트
- **작업**:
  1. 로그인 상태에서 페이지 새로고침
  2. 로그인 상태 유지 확인
- **체크포인트**: 토큰이 localStorage에 저장되어 상태 유지됨

---

## 4.3 에러 케이스 테스트

### 4.3.1 중복 회원가입 테스트
- **담당**: 메인 에이전트
- **작업**: 같은 username/email로 회원가입 시도
- **체크포인트**: 에러 메시지 표시

### 4.3.2 잘못된 로그인 테스트
- **담당**: 메인 에이전트
- **작업**: 잘못된 비밀번호로 로그인 시도
- **체크포인트**: 에러 메시지 표시

### 4.3.3 약한 비밀번호 테스트
- **담당**: 메인 에이전트
- **작업**: 숫자만 또는 영문만으로 회원가입 시도
- **체크포인트**: 유효성 검사 에러 표시

---

# 체크리스트

## Phase 1: DB (db-agent)
- [ ] User 모델 생성 (9개 체크포인트)
- [ ] CRUD 함수 구현 (15개 체크포인트)
- [ ] DB 테스트 작성 및 통과 (13개 체크포인트)

## Phase 2: BE (be-agent)
- [ ] 환경 준비 (3개 체크포인트)
- [ ] 인증 유틸리티 구현 (11개 체크포인트)
- [ ] Pydantic 스키마 정의 (9개 체크포인트)
- [ ] 인증 의존성 구현 (8개 체크포인트)
- [ ] API 엔드포인트 구현 (15개 체크포인트)
- [ ] API 테스트 작성 및 통과 (12개 체크포인트)

## Phase 3: FE (fe-agent)
- [ ] 환경 준비 (2개 체크포인트)
- [ ] 타입 정의 (5개 체크포인트)
- [ ] API 연동 함수 (12개 체크포인트)
- [ ] 인증 Context (11개 체크포인트)
- [ ] 로그인 페이지 (11개 체크포인트)
- [ ] 회원가입 페이지 (12개 체크포인트)
- [ ] Navbar 컴포넌트 (6개 체크포인트)
- [ ] ProtectedRoute (2개 체크포인트)
- [ ] 홈페이지 업데이트 (1개 체크포인트)

## Phase 4: 통합 테스트
- [ ] 백엔드 실행 및 테스트 (3개 체크포인트)
- [ ] 프론트엔드 실행 및 테스트 (6개 체크포인트)
- [ ] 에러 케이스 테스트 (3개 체크포인트)

---

**총 체크포인트: 170개**

각 체크포인트는 독립적으로 완료할 수 있는 최소 단위 작업입니다.
