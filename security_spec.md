# Security Specification — Đấu Trường Văn Học

## Roles (Phân quyền 2 cấp Quản trị + Sinh viên)
1. **Student (`student`)**: Authenticated via Google Sign-In (`email_verified == true`), non-`@fpt.edu.vn` account.
2. **Lecturer Level 2 (`admin` Mức 2)**: Authenticated via Google Sign-In (`email_verified == true`) with `@fpt.edu.vn` email suffix (or UID listed in `/admins/{uid}`), plus server-verified admin password for dashboard unlock. Read-only access to all student attempts (`list`/`get`), cannot delete attempts or modify `/admins`.
3. **Super Admin Level 1 (`admin` Mức 1)**: Authenticated via Google Sign-In (`email_verified == true`) as `trangpt50@fpt.edu.vn`, plus server-verified admin password. Full access including deleting erroneous attempts and managing `/admins`.

## Authorization Rules
- `/users/{userId}`:
  - Read: Owner (`request.auth.uid == userId`) or Admin (Level 1 or 2).
  - Create: Owner only; cannot self-assign `role == 'teacher'` unless `isAdmin()`.
  - Update: Owner only (cannot change `role` or `uid` unless `isAdmin()`) or Super Admin (Level 1).
  - Delete: Super Admin (Level 1) only.
- `/attempts/{attemptId}`:
  - Read: Admin (Level 1 or Level 2) OR Owner (`resource.data.uid == request.auth.uid`) — strictly enforces that students only read their own history.
  - Create: Authenticated user only (`request.resource.data.uid == request.auth.uid`), immutable server timestamp (`createdAt == request.time`), validated score/count bounds, bounded `details` array (<= 50 items). Every submission creates a new document (`addDoc`), never overwriting prior attempts.
  - Update: Denied (`false`) so submitted scores cannot be altered by anyone.
  - Delete: Super Admin (Level 1) only.
- `/admins/{userId}`:
  - Read: Owner (`request.auth.uid == userId`) or Admin (Level 1 or 2).
  - Write (Create / Update / Delete): Super Admin (Level 1) only.
- `/test/connection`:
  - Read: Authenticated (`isAuthenticated()`) for startup connection verification; Write: Denied (`false`).
