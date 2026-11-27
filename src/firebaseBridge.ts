import { initializeApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  type User,
} from 'firebase/auth';
import {
  getFirestore,
  doc,
  getDoc,
  getDocFromServer,
  setDoc,
  addDoc,
  deleteDoc,
  collection,
  query,
  where,
  onSnapshot,
  serverTimestamp,
  Timestamp,
  type Unsubscribe,
} from 'firebase/firestore';
import firebaseConfig from '../firebase-applet-config.json';

const BOOTSTRAPPED_ADMIN_EMAIL = 'trangpt50@fpt.edu.vn';
const FPT_TEACHER_REGEX = /^[^@]+@fpt\.edu\.vn$/i;

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({ prompt: 'select_account' });

export type OperationType = 'create' | 'update' | 'delete' | 'list' | 'get' | 'write';

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId: string | undefined;
    email: string | null | undefined;
    emailVerified: boolean | undefined;
    isAnonymous: boolean | undefined;
    providerInfo: Array<{
      providerId: string;
      displayName: string | null;
      email: string | null;
      photoUrl: string | null;
    }>;
  };
}

export interface AttemptDetailItem {
  q: string;
  options: string[];
  chosen: string | null;
  ans: string;
  isRight: boolean;
  explain: string;
  lessonId: number;
}

export interface AttemptRecordPayload {
  fullName: string;
  email: string;
  className: string;
  teacherName: string;
  examTitle: string;
  mode: 'game' | 'exam';
  correct: number;
  wrong: number;
  skipped: number;
  total: number;
  correctCount: string;
  score: number;
  durationSeconds: number;
  details: AttemptDetailItem[];
  clientTimestamp: number;
}

export interface AttemptRecordView extends AttemptRecordPayload {
  id: string;
  uid: string;
  timestamp: number;
  syncStatus: string;
}

export interface UserProfileView {
  uid: string;
  fullName: string;
  email: string;
  role: 'student' | 'teacher';
  className: string;
  teacherName: string;
}

function handleFirestoreError(error: unknown, operationType: OperationType, path: string | null): Error {
  const errMsg = error instanceof Error ? error.message : String(error);
  const errInfo: FirestoreErrorInfo = {
    error: errMsg,
    operationType,
    path,
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      providerInfo:
        auth.currentUser?.providerData.map((provider) => ({
          providerId: provider.providerId,
          displayName: provider.displayName,
          email: provider.email,
          photoUrl: provider.photoURL,
        })) || [],
    },
  };
  console.error('Firestore Error:', JSON.stringify(errInfo));
  return new Error(errMsg);
}

async function testConnection(): Promise<void> {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration: Firestore client is offline.');
    }
  }
}

void testConnection();

let currentUser: User | null = null;
let currentIsAdmin = false;
let currentAdminLevel: 0 | 1 | 2 = 0;
let currentProfile: UserProfileView | null = null;
let studentAttemptsUnsub: Unsubscribe | null = null;
let adminAttemptsUnsub: Unsubscribe | null = null;

// Admin password session token kept strictly in memory (never localStorage)
let adminSessionToken = '';
let adminSessionExpiresAt = 0;

function toMillis(val: unknown, fallback = Date.now()): number {
  if (val instanceof Timestamp) return val.toMillis();
  if (val && typeof val === 'object' && 'toMillis' in val && typeof (val as { toMillis: () => number }).toMillis === 'function') {
    return (val as { toMillis: () => number }).toMillis();
  }
  if (typeof val === 'number' && Number.isFinite(val)) return val;
  return fallback;
}

function mapAttemptDoc(docId: string, raw: Record<string, unknown>): AttemptRecordView {
  const createdMs = toMillis(raw.createdAt, Number(raw.clientTimestamp) || Date.now());
  const correct = Number(raw.correct) || 0;
  const total = Math.max(1, Number(raw.total) || 1);
  const wrong = Number(raw.wrong) || 0;
  const skipped = Number(raw.skipped) || 0;
  return {
    id: docId,
    uid: String(raw.uid || ''),
    fullName: String(raw.fullName || 'Sinh viên'),
    email: String(raw.email || ''),
    className: String(raw.className || ''),
    teacherName: String(raw.teacherName || ''),
    examTitle: String(raw.examTitle || 'Bài luyện tập'),
    mode: raw.mode === 'exam' ? 'exam' : 'game',
    correct,
    wrong,
    skipped,
    total,
    correctCount: String(raw.correctCount || `${correct}/${total} câu`),
    score: Number(raw.score) || 0,
    durationSeconds: Number(raw.durationSeconds) || 0,
    details: Array.isArray(raw.details) ? (raw.details as AttemptDetailItem[]) : [],
    clientTimestamp: Number(raw.clientTimestamp) || createdMs,
    timestamp: createdMs,
    syncStatus: '☁️ Đã đồng bộ trực tuyến',
  };
}

function notifyAuthBridge(): void {
  const win = window as unknown as {
    onFirebaseAuthReady?: (info: {
      signedIn: boolean;
      uid: string;
      email: string;
      displayName: string;
      isAdmin: boolean;
      adminLevel: 0 | 1 | 2;
      profile: UserProfileView | null;
    }) => void;
  };
  if (typeof win.onFirebaseAuthReady === 'function') {
    win.onFirebaseAuthReady({
      signedIn: Boolean(currentUser),
      uid: currentUser?.uid || '',
      email: (currentUser?.email || '').toLowerCase(),
      displayName: currentUser?.displayName || '',
      isAdmin: currentIsAdmin,
      adminLevel: currentAdminLevel,
      profile: currentProfile,
    });
  }
}

function attachStudentAttemptsListener(uid: string): void {
  if (studentAttemptsUnsub) {
    studentAttemptsUnsub();
    studentAttemptsUnsub = null;
  }
  const q = query(collection(db, 'attempts'), where('uid', '==', uid));
  studentAttemptsUnsub = onSnapshot(
    q,
    (snapshot) => {
      const items = snapshot.docs
        .map((d) => mapAttemptDoc(d.id, d.data() as Record<string, unknown>))
        .sort((a, b) => b.timestamp - a.timestamp);
      const win = window as unknown as { onStudentAttemptsUpdate?: (list: AttemptRecordView[]) => void };
      if (typeof win.onStudentAttemptsUpdate === 'function') {
        win.onStudentAttemptsUpdate(items);
      }
    },
    (err) => {
      handleFirestoreError(err, 'list', 'attempts');
    }
  );
}

async function resolveAdminAndProfile(user: User): Promise<void> {
  const email = (user.email || '').trim().toLowerCase();
  let adminLevel: 0 | 1 | 2 = 0;
  if (user.emailVerified) {
    if (email === BOOTSTRAPPED_ADMIN_EMAIL) {
      adminLevel = 1;
    } else if (FPT_TEACHER_REGEX.test(email)) {
      adminLevel = 2;
    } else {
      try {
        const adminSnap = await getDoc(doc(db, 'admins', user.uid));
        if (adminSnap.exists()) {
          adminLevel = 2;
        }
      } catch {
        // Not an admin or missing permission — safe default 0
      }
    }
  }
  currentAdminLevel = adminLevel;
  currentIsAdmin = adminLevel > 0;

  try {
    const profileSnap = await getDoc(doc(db, 'users', user.uid));
    if (profileSnap.exists()) {
      const data = profileSnap.data() as Record<string, unknown>;
      currentProfile = {
        uid: user.uid,
        fullName: String(data.fullName || user.displayName || ''),
        email: String(data.email || email).toLowerCase(),
        role: data.role === 'teacher' ? 'teacher' : 'student',
        className: String(data.className || ''),
        teacherName: String(data.teacherName || ''),
      };
    } else {
      currentProfile = null;
    }
  } catch (err) {
    handleFirestoreError(err, 'get', `users/${user.uid}`);
    currentProfile = null;
  }
}

onAuthStateChanged(auth, async (user) => {
  currentUser = user;
  if (!user) {
    currentIsAdmin = false;
    currentAdminLevel = 0;
    currentProfile = null;
    adminSessionToken = '';
    adminSessionExpiresAt = 0;
    if (studentAttemptsUnsub) {
      studentAttemptsUnsub();
      studentAttemptsUnsub = null;
    }
    if (adminAttemptsUnsub) {
      adminAttemptsUnsub();
      adminAttemptsUnsub = null;
    }
    notifyAuthBridge();
    const win = window as unknown as { onStudentAttemptsUpdate?: (list: AttemptRecordView[]) => void };
    if (typeof win.onStudentAttemptsUpdate === 'function') {
      win.onStudentAttemptsUpdate([]);
    }
    return;
  }

  await resolveAdminAndProfile(user);
  attachStudentAttemptsListener(user.uid);
  notifyAuthBridge();
});

const bridge = {
  async signInWithGoogle() {
    const result = await signInWithPopup(auth, googleProvider);
    currentUser = result.user;
    await resolveAdminAndProfile(result.user);
    attachStudentAttemptsListener(result.user.uid);
    notifyAuthBridge();
    return {
      uid: result.user.uid,
      email: (result.user.email || '').toLowerCase(),
      displayName: result.user.displayName || '',
      isAdmin: currentIsAdmin,
      adminLevel: currentAdminLevel,
      profile: currentProfile,
    };
  },

  async signOutGoogle() {
    adminSessionToken = '';
    adminSessionExpiresAt = 0;
    currentAdminLevel = 0;
    currentIsAdmin = false;
    if (studentAttemptsUnsub) {
      studentAttemptsUnsub();
      studentAttemptsUnsub = null;
    }
    if (adminAttemptsUnsub) {
      adminAttemptsUnsub();
      adminAttemptsUnsub = null;
    }
    await signOut(auth);
  },

  getAuthState() {
    return {
      signedIn: Boolean(currentUser),
      uid: currentUser?.uid || '',
      email: (currentUser?.email || '').toLowerCase(),
      displayName: currentUser?.displayName || '',
      isAdmin: currentIsAdmin,
      adminLevel: currentAdminLevel,
      profile: currentProfile,
    };
  },

  async saveUserProfile(input: {
    fullName: string;
    email: string;
    role: 'student' | 'teacher';
    className: string;
    teacherName: string;
  }) {
    if (!currentUser) throw new Error('Vui lòng đăng nhập Google trước.');
    const safeRole: 'student' | 'teacher' =
      input.role === 'teacher' && currentIsAdmin ? 'teacher' : 'student';
    const payload = {
      uid: currentUser.uid,
      fullName: input.fullName.trim().slice(0, 120),
      email: (currentUser.email || input.email).trim().toLowerCase().slice(0, 200),
      role: safeRole,
      className: (input.className || '').trim().slice(0, 60),
      teacherName: (input.teacherName || '').trim().slice(0, 120),
      updatedAt: serverTimestamp(),
    };
    try {
      await setDoc(doc(db, 'users', currentUser.uid), payload, { merge: true });
      currentProfile = {
        uid: payload.uid,
        fullName: payload.fullName,
        email: payload.email,
        role: payload.role,
        className: payload.className,
        teacherName: payload.teacherName,
      };
      return currentProfile;
    } catch (err) {
      throw handleFirestoreError(err, 'write', `users/${currentUser.uid}`);
    }
  },

  async saveAttempt(payload: AttemptRecordPayload): Promise<AttemptRecordView> {
    if (!currentUser) {
      throw new Error('Bạn cần đăng nhập tài khoản Google để đồng bộ bài làm.');
    }
    const cleanTotal = Math.max(1, Math.min(100, Math.round(Number(payload.total) || 1)));
    const cleanCorrect = Math.max(0, Math.min(cleanTotal, Math.round(Number(payload.correct) || 0)));
    const cleanWrong = Math.max(0, Math.min(cleanTotal, Math.round(Number(payload.wrong) || 0)));
    const cleanSkipped = Math.max(0, Math.min(cleanTotal, Math.round(Number(payload.skipped) || 0)));
    const cleanScore = Math.max(0, Math.min(10, Number(payload.score) || 0));
    const cleanDuration = Math.max(0, Math.min(86400, Math.round(Number(payload.durationSeconds) || 0)));
    const cleanDetails = Array.isArray(payload.details)
      ? payload.details.slice(0, 50).map((d) => ({
          q: String(d.q || '').slice(0, 500),
          options: Array.isArray(d.options) ? d.options.slice(0, 4).map((o) => String(o || '').slice(0, 300)) : [],
          chosen: d.chosen ? String(d.chosen).slice(0, 4) : null,
          ans: String(d.ans || 'A').slice(0, 4),
          isRight: Boolean(d.isRight),
          explain: String(d.explain || '').slice(0, 500),
          lessonId: Number(d.lessonId) || 1,
        }))
      : [];

    const cleanMode: 'game' | 'exam' = payload.mode === 'exam' ? 'exam' : 'game';
    const docData = {
      uid: currentUser.uid,
      fullName: (payload.fullName || currentUser.displayName || 'Sinh viên').trim().slice(0, 120),
      email: (currentUser.email || payload.email || '').trim().toLowerCase().slice(0, 200),
      className: (payload.className || '').trim().slice(0, 60),
      teacherName: (payload.teacherName || 'Cô Trang').trim().slice(0, 120),
      examTitle: (payload.examTitle || 'Bài luyện tập').trim().slice(0, 240),
      mode: cleanMode,
      correct: cleanCorrect,
      wrong: cleanWrong,
      skipped: cleanSkipped,
      total: cleanTotal,
      correctCount: `${cleanCorrect}/${cleanTotal} câu`,
      score: Number(cleanScore.toFixed(2)),
      durationSeconds: cleanDuration,
      details: cleanDetails,
      clientTimestamp: Number(payload.clientTimestamp) || Date.now(),
      createdAt: serverTimestamp(),
    };

    try {
      const ref = await addDoc(collection(db, 'attempts'), docData);
      return {
        id: ref.id,
        uid: docData.uid,
        fullName: docData.fullName,
        email: docData.email,
        className: docData.className,
        teacherName: docData.teacherName,
        examTitle: docData.examTitle,
        mode: docData.mode,
        correct: docData.correct,
        wrong: docData.wrong,
        skipped: docData.skipped,
        total: docData.total,
        correctCount: docData.correctCount,
        score: docData.score,
        durationSeconds: docData.durationSeconds,
        details: docData.details,
        clientTimestamp: docData.clientTimestamp,
        timestamp: docData.clientTimestamp,
        syncStatus: '☁️ Đã đồng bộ trực tuyến',
      };
    } catch (err) {
      throw handleFirestoreError(err, 'create', 'attempts');
    }
  },

  async getAdminAuthStatus(): Promise<{ configured: boolean; mode: 'env' | 'claimed' | 'claim_required' }> {
    const res = await fetch('/api/admin/status');
    if (!res.ok) throw new Error('Không kiểm tra được trạng thái mật khẩu quản trị.');
    return res.json();
  },

  async claimAdminPassword(password: string): Promise<{ ok: boolean; error?: string }> {
    if (!currentUser) {
      return { ok: false, error: 'Vui lòng đăng nhập tài khoản Google Giảng viên trước.' };
    }
    const idToken = await currentUser.getIdToken();
    const res = await fetch('/api/admin/claim', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${idToken}`,
      },
      body: JSON.stringify({ password }),
    });
    const data = await res.json();
    if (!res.ok) {
      return { ok: false, error: data.error || 'Không thể thiết lập mật khẩu quản trị.' };
    }
    adminSessionToken = data.token || '';
    adminSessionExpiresAt = Number(data.expiresAt) || 0;
    return { ok: true };
  },

  async verifyAdminPassword(password: string): Promise<{ ok: boolean; adminLevel?: number; error?: string }> {
    if (!currentUser) {
      return { ok: false, error: 'Vui lòng đăng nhập tài khoản Google Giáo viên trước.' };
    }
    const idToken = await currentUser.getIdToken();
    const res = await fetch('/api/admin/verify-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${idToken}`,
      },
      body: JSON.stringify({ password }),
    });
    const data = await res.json();
    if (!res.ok) {
      return { ok: false, error: data.error || 'Mật khẩu quản trị chưa chính xác.' };
    }
    adminSessionToken = data.token || '';
    adminSessionExpiresAt = Number(data.expiresAt) || 0;
    return { ok: true, adminLevel: Number(data.adminLevel) || currentAdminLevel };
  },

  async isAdminSessionUnlocked(): Promise<boolean> {
    if (!adminSessionToken || Date.now() > adminSessionExpiresAt) {
      adminSessionToken = '';
      adminSessionExpiresAt = 0;
      return false;
    }
    try {
      const res = await fetch('/api/admin/session', {
        headers: { Authorization: `Bearer ${adminSessionToken}` },
      });
      if (!res.ok) {
        adminSessionToken = '';
        adminSessionExpiresAt = 0;
        return false;
      }
      return true;
    } catch {
      return false;
    }
  },

  lockAdminSession(): void {
    adminSessionToken = '';
    adminSessionExpiresAt = 0;
    if (adminAttemptsUnsub) {
      adminAttemptsUnsub();
      adminAttemptsUnsub = null;
    }
  },

  subscribeAllAttemptsForAdmin(
    onUpdate: (list: AttemptRecordView[]) => void,
    onError: (msg: string) => void
  ): void {
    if (!currentUser || !currentIsAdmin) {
      onError('Tài khoản Google hiện tại chưa được cấp quyền Giảng viên quản trị trên Firestore.');
      return;
    }
    if (!adminSessionToken || Date.now() > adminSessionExpiresAt) {
      onError('Vui lòng nhập mật khẩu Quản trị trước.');
      return;
    }
    if (adminAttemptsUnsub) {
      adminAttemptsUnsub();
      adminAttemptsUnsub = null;
    }
    adminAttemptsUnsub = onSnapshot(
      collection(db, 'attempts'),
      (snapshot) => {
        const list = snapshot.docs
          .map((d) => mapAttemptDoc(d.id, d.data() as Record<string, unknown>))
          .sort((a, b) => b.timestamp - a.timestamp);
        onUpdate(list);
      },
      (err) => {
        const mapped = handleFirestoreError(err, 'list', 'attempts');
        onError(mapped.message || 'Không có quyền đọc toàn bộ bảng điểm.');
      }
    );
  },

  unsubscribeAdminAttempts(): void {
    if (adminAttemptsUnsub) {
      adminAttemptsUnsub();
      adminAttemptsUnsub = null;
    }
  },

  async deleteAttempt(attemptId: string): Promise<void> {
    if (!currentUser || currentAdminLevel !== 1) {
      throw new Error('Chỉ Quản trị viên chính (Mức 1) mới có quyền xóa lượt làm bài.');
    }
    const cleanId = attemptId.trim();
    if (!cleanId) throw new Error('Mã lượt làm bài không hợp lệ.');
    try {
      await deleteDoc(doc(db, 'attempts', cleanId));
    } catch (err) {
      throw handleFirestoreError(err, 'delete', `attempts/${cleanId}`);
    }
  },

  async grantAdminAccess(targetUid: string, targetEmail: string): Promise<void> {
    if (!currentUser || currentAdminLevel !== 1) {
      throw new Error('Chỉ Quản trị viên chính (Mức 1) mới có quyền thêm giảng viên ngoài hệ thống.');
    }
    const cleanUid = targetUid.trim();
    const cleanEmail = targetEmail.trim().toLowerCase();
    if (!cleanUid || !cleanEmail.includes('@')) {
      throw new Error('Vui lòng nhập đúng UID và Email hợp lệ.');
    }
    try {
      await setDoc(doc(db, 'admins', cleanUid), {
        email: cleanEmail,
        addedAt: serverTimestamp(),
      });
    } catch (err) {
      throw handleFirestoreError(err, 'write', `admins/${cleanUid}`);
    }
  },
};

(window as unknown as { LiteraryFirebase: typeof bridge }).LiteraryFirebase = bridge;
export default bridge;
