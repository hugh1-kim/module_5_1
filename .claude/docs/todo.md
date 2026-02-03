# TODO List

## Feature: 로그인 기능 구현

### DB 작업 (db-agent)
- [ ] User 테이블 모델 생성
  - [ ] id (Primary Key)
  - [ ] username (Unique, Not Null)
  - [ ] email (Unique, Not Null)
  - [ ] password_hash (Not Null)
  - [ ] created_at (Timestamp)
  - [ ] updated_at (Timestamp)
- [ ] User CRUD 함수 구현
  - [ ] create_user (회원가입용)
  - [ ] get_user_by_username (로그인 인증용)
  - [ ] get_user_by_email (이메일 조회용)
- [ ] DB 테스트 작성
  - [ ] User 생성 테스트
  - [ ] username 중복 제약조건 테스트
  - [ ] email 중복 제약조건 테스트

### BE 작업 (be-agent)
- [ ] 인증 관련 유틸리티 구현
  - [ ] 비밀번호 해싱 함수 (bcrypt)
  - [ ] 비밀번호 검증 함수
  - [ ] JWT 토큰 생성 함수
  - [ ] JWT 토큰 검증 함수
- [ ] Pydantic 스키마 정의
  - [ ] UserCreate (회원가입 요청)
  - [ ] UserLogin (로그인 요청)
  - [ ] UserResponse (사용자 정보 응답)
  - [ ] Token (토큰 응답)
- [ ] API 엔드포인트 구현
  - [ ] POST /api/auth/register (회원가입)
  - [ ] POST /api/auth/login (로그인)
  - [ ] GET /api/auth/me (현재 사용자 정보 조회)
- [ ] 인증 미들웨어/의존성 구현
  - [ ] get_current_user (JWT 토큰 검증)
- [ ] API 테스트 작성
  - [ ] 회원가입 테스트
  - [ ] 로그인 성공 테스트
  - [ ] 로그인 실패 테스트 (잘못된 비밀번호)
  - [ ] 토큰 검증 테스트

### FE 작업 (fe-agent)
- [ ] 로그인 페이지 구현
  - [ ] /login 라우트 생성
  - [ ] 로그인 폼 UI 구현 (username/email, password)
  - [ ] 폼 유효성 검사
  - [ ] 에러 메시지 표시
- [ ] 회원가입 페이지 구현
  - [ ] /register 라우트 생성
  - [ ] 회원가입 폼 UI 구현
  - [ ] 비밀번호 확인 필드
  - [ ] 폼 유효성 검사
- [ ] API 연동
  - [ ] 로그인 API 호출 함수
  - [ ] 회원가입 API 호출 함수
  - [ ] 토큰 저장 (localStorage/cookie)
  - [ ] 로그인 상태 관리 (Context/Zustand)
- [ ] 인증 보호 라우트 구현
  - [ ] 로그인 여부 확인 컴포넌트/HOC
  - [ ] 미인증 시 로그인 페이지로 리다이렉트
- [ ] 네비게이션 업데이트
  - [ ] 로그인/회원가입 링크 추가
  - [ ] 로그아웃 버튼 추가
  - [ ] 사용자 정보 표시
- [ ] 컴포넌트 테스트 작성
  - [ ] 로그인 폼 렌더링 테스트
  - [ ] 회원가입 폼 렌더링 테스트
  - [ ] 폼 제출 테스트

---

## 작업 순서 (권장)
1. **DB 작업** (db-agent) - User 모델 및 CRUD 구현
2. **BE 작업** (be-agent) - 인증 API 엔드포인트 구현
3. **FE 작업** (fe-agent) - 로그인/회원가입 페이지 및 API 연동

## 추가 고려사항
- [ ] 비밀번호 강도 검증 정책 결정
- [ ] JWT 토큰 만료 시간 설정
- [ ] Refresh Token 구현 여부 결정
- [ ] 소셜 로그인 (OAuth) 추가 여부 결정
