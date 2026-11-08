import assert from 'node:assert/strict';
import { test } from 'node:test';
import { authHeaders, createTestApi, json } from './helpers.mjs';

test('authenticates users and provides protected document, accounting, media, and security APIs', async (t) => {
  const api = await createTestApi();
  t.after(() => api.close());
  const { request } = api;

  const status = await request('/api/auth/status');
  assert.deepEqual(await status.json(), { configured: false });
  assert.match(status.headers.get('content-security-policy'), /img-src 'self' data: blob:;/);
  assert.equal((await request('/api/documents')).status, 401);
  assert.equal((await request('/api/security/summary')).status, 401);
  assert.equal((await request('/api/security/procedures')).status, 401);

  const registration = await request('/api/auth/register', json('POST', {
    username: 'Site Owner',
    ownerLoginId: 'private-owner-22',
    setupKey: 'wrong-key',
    password: 'very-long-test-password'
  }));
  assert.equal(registration.status, 403);
  const validRegistration = await request('/api/auth/register', json('POST', {
    username: 'Site Owner',
    ownerLoginId: 'private-owner-22',
    setupKey: 'test-only-initial-admin-key-long-enough',
    password: 'very-long-test-password'
  }));
  assert.equal(validRegistration.status, 201);
  const admin = await validRegistration.json();
  assert.equal((await request('/api/organization')).status, 401);
  const defaultOrganization = await request('/api/organization', {
    headers: authHeaders(admin.token)
  });
  const defaultOrganizationData = await defaultOrganization.json();
  assert.deepEqual({
    organization_name: defaultOrganizationData.organization_name,
    work_location: defaultOrganizationData.work_location
  }, {
    organization_name: 'المربع الجديد',
    work_location: 'شمال الرياض'
  });
  assert.ok(defaultOrganizationData.updated_at);
  assert.equal((await request('/api/organization', json('PUT', {
    organizationName: 'المربع الجديد',
    workLocation: 'شمال الرياض'
  }))).status, 401);
  assert.equal((await request('/api/organization', json('PUT', {
    organizationName: 'المربع الجديد',
    workLocation: 'شمال الرياض'
  }, admin.token))).status, 200);
  assert.equal((await request('/api/organization', json('PUT', {
    organizationName: '',
    workLocation: 'مكان'
  }, admin.token))).status, 400);
  assert.equal((await request('/api/auth/register', json('POST', {
    username: 'Another User',
    ownerLoginId: 'another-owner-23',
    password: 'very-long-test-password'
  }))).status, 403);
  assert.equal((await (await request('/api/auth/me', { headers: authHeaders(admin.token) })).json()).role, 'admin');
  const ownerProfile = await (await request('/api/auth/me', { headers: authHeaders(admin.token) })).json();
  assert.equal(Object.hasOwn(ownerProfile, 'owner_login_id'), false);
  assert.equal(Object.hasOwn(ownerProfile, 'identity_number'), false);

  const createdUser = await request('/api/users', json('POST', {
    username: 'Security Staff',
    identityNumber: '1000000003',
    password: 'another-long-test-password'
  }, admin.token));
  assert.equal(createdUser.status, 201);
  const user = await createdUser.json();
  assert.equal(user.role, 'staff');
  assert.equal(user.identity_number, '1000000003');
  assert.equal(Object.hasOwn(user, 'owner_login_id'), false);
  const listedUsers = await (await request('/api/users', { headers: authHeaders(admin.token) })).json();
  assert.equal(Object.hasOwn(listedUsers[0], 'owner_login_id'), false);
  const ownerLoginChange = await request(`/api/users/${listedUsers.find((entry) => entry.role === 'admin').id}/owner-login`, json('PATCH', {
    ownerLoginId: 'owner-access-77'
  }, admin.token));
  assert.equal(ownerLoginChange.status, 200);
  const ownerLogin = await request('/api/auth/login', json('POST', {
    loginId: 'owner-access-77',
    password: 'very-long-test-password'
  }));
  assert.equal(ownerLogin.status, 200);
  const legacyOwnerLogin = await request('/api/auth/login', json('POST', {
    loginId: 'private-owner-22',
    password: 'very-long-test-password'
  }));
  assert.equal(legacyOwnerLogin.status, 401);
  const updatedIdentity = await request(`/api/users/${user.id}/identity`, json('PATCH', {
    identityNumber: '1000000004'
  }, admin.token));
  assert.equal(updatedIdentity.status, 200);
  assert.equal((await updatedIdentity.json()).identity_number, '1000000004');
  const oldIdentityLogin = await request('/api/auth/login', json('POST', {
    loginId: '1000000003',
    password: 'another-long-test-password'
  }));
  assert.equal(oldIdentityLogin.status, 401);
  const login = await request('/api/auth/login', json('POST', {
    loginId: '1000000004',
    password: 'another-long-test-password'
  }));
  const staff = await login.json();
  assert.equal((await request('/api/organization', {
    headers: authHeaders(staff.token)
  })).status, 200);
  assert.equal((await request('/api/organization', json('PUT', {
    organizationName: 'تعديل موظف',
    workLocation: 'موقع غير مصرح'
  }, staff.token))).status, 403);
  assert.equal((await request('/api/users', { headers: authHeaders(staff.token) })).status, 403);
  assert.equal((await request(`/api/users/${user.id}/identity`, json('PATCH', {
    identityNumber: '1000000005'
  }, staff.token))).status, 403);
  assert.equal((await request(`/api/users/${listedUsers.find((entry) => entry.role === 'admin').id}/owner-login`, json('PATCH', {
    ownerLoginId: 'staff-owner-99'
  }, staff.token))).status, 403);
  assert.equal((await request('/api/users', json('POST', {
    username: 'Duplicate User',
    identityNumber: '1000000004',
    password: 'another-long-test-password'
  }, admin.token))).status, 409);

  const featureRequest = await request('/api/feature-requests', json('POST', {
    category: 'تحسين أداء',
    message: 'أحتاج تسريع البحث في سجل المركبات.'
  }, staff.token));
  assert.equal(featureRequest.status, 201);
  const featureRequestEntry = await featureRequest.json();
  assert.equal((await (await request('/api/feature-requests', {
    headers: authHeaders(staff.token)
  })).json()).length, 1);
  const adminRequests = await (await request('/api/feature-requests', {
    headers: authHeaders(admin.token)
  })).json();
  assert.equal(adminRequests[0].requester_name, 'Security Staff');
  assert.equal((await request(`/api/feature-requests/${featureRequestEntry.id}`, json('PATCH', {
    status: 'قيد المراجعة'
  }, staff.token))).status, 403);
  assert.equal((await request(`/api/feature-requests/${featureRequestEntry.id}`, json('PATCH', {
    status: 'قيد المراجعة'
  }, admin.token))).status, 200);

  const analyzed = await request('/api/documents/analyze', json('POST', {
    title: 'عقد تجريبي',
    content: 'اتفق الطرف الأول والطرف الثاني على توقيع العقد.'
  }, staff.token));
  assert.equal(analyzed.status, 201);
  const document = await analyzed.json();
  assert.equal(document.analysis.score, 29);
  assert.equal(document.analysis.clauses.find((clause) => clause.name === 'التوقيع').present, true);
  assert.equal((await request('/api/documents', { headers: authHeaders(staff.token) })).status, 200);

  const invalidDate = await request('/api/accounting/transactions', json('POST', {
    kind: 'expense',
    description: 'تاريخ غير صالح',
    amount: 10,
    date: '2026-02-30'
  }, staff.token));
  assert.equal(invalidDate.status, 400);
  for (const [kind, description, amount] of [
    ['income', 'فاتورة عميل', 1200],
    ['purchase', '=SUM(1,2)', 50]
  ]) {
    const response = await request('/api/accounting/transactions', json('POST', {
      kind, description, amount, date: '2026-10-01'
    }, staff.token));
    assert.equal(response.status, 201);
  }
  const summary = await (await request('/api/accounting/summary?year=2026', {
    headers: authHeaders(staff.token)
  })).json();
  assert.equal(summary.income, 1200);
  assert.equal(summary.expenses, 50);
  const exportResponse = await request('/api/accounting/export.csv', { headers: authHeaders(staff.token) });
  assert.match(await exportResponse.text(), /"'=SUM\(1,2\)"/);

  const upload = new FormData();
  upload.append('category', 'مستندات');
  upload.append('file', new Blob(['test image content'], { type: 'image/png' }), 'test.png');
  const mediaResponse = await request('/api/media', {
    method: 'POST',
    headers: authHeaders(staff.token),
    body: upload
  });
  assert.equal(mediaResponse.status, 201);
  const media = await mediaResponse.json();
  assert.equal(media.original_name, 'test.png');
  const preview = await request(`/api/media/${media.id}/preview`, { headers: authHeaders(staff.token) });
  assert.equal(preview.status, 200);

  const rejectedUpload = new FormData();
  rejectedUpload.append('file', new Blob(['not an image'], { type: 'image/svg+xml' }), 'unsafe.svg');
  assert.equal((await request('/api/media', {
    method: 'POST',
    headers: authHeaders(staff.token),
    body: rejectedUpload
  })).status, 400);

  const accessForm = new FormData();
  accessForm.append('people', JSON.stringify([
    { name: 'زائر أول', identityNumber: 'ID-101', phone: '0500000001' },
    { name: 'زائر ثان', identityNumber: 'ID-102', phone: '0500000002' }
  ]));
  accessForm.append('organization', 'شركة تجريبية');
  accessForm.append('purpose', 'زيارة عمل');
  accessForm.append('gate', 'البوابة الرئيسية');
  accessForm.append('vehiclePlate', 'XYZ 987');
  accessForm.append('vehiclePhoto', new Blob(['test vehicle image'], { type: 'image/png' }), 'vehicle.png');
  const access = await request('/api/security/access', {
    method: 'POST',
    headers: authHeaders(staff.token),
    body: accessForm
  });
  assert.equal(access.status, 201);
  const accessRecord = await access.json();
  assert.equal(accessRecord.person_count, 2);
  assert.ok(accessRecord.vehicle_photo_media_id);
  assert.match(accessRecord.vehicle_code, /^VH-[0-9A-F]{12}$/);
  assert.equal((await request(`/api/media/${accessRecord.vehicle_photo_media_id}/preview`, {
    headers: authHeaders(staff.token)
  })).status, 200);
  assert.equal((await request(`/api/media/${accessRecord.vehicle_photo_media_id}`, {
    method: 'DELETE',
    headers: authHeaders(staff.token)
  })).status, 409);
  const accessList = await (await request('/api/security/access?status=inside&search=ID-102', {
    headers: authHeaders(staff.token)
  })).json();
  assert.equal(accessList.length, 1);
  assert.equal(accessList[0].members.length, 2);
  const securitySummary = await (await request('/api/security/summary', {
    headers: authHeaders(staff.token)
  })).json();
  assert.equal(securitySummary.people_inside, 2);
  assert.equal(securitySummary.active_visits, 1);
  const exitResponse = await request(`/api/security/access/${accessRecord.id}/exit`, {
    method: 'POST',
    headers: authHeaders(staff.token)
  });
  assert.equal(exitResponse.status, 200);
  assert.ok((await exitResponse.json()).exited_at);
  assert.equal((await request(`/api/security/access/${accessRecord.id}/exit`, {
    method: 'POST',
    headers: authHeaders(staff.token)
  })).status, 409);

  const validUntil = new Date();
  validUntil.setUTCDate(validUntil.getUTCDate() + 7);
  const permitForm = new FormData();
  for (const [key, value] of Object.entries({
    permitNumber: 'VP-001',
    vehiclePlate: 'XYZ 987',
    driverName: 'سائق تجريبي',
    identityNumber: 'ID-201',
    phone: '0500000003',
    organization: 'شركة تجريبية',
    purpose: 'توريد',
    validFrom: '2020-01-01',
    validUntil: validUntil.toISOString().slice(0, 10)
  })) permitForm.append(key, value);
  permitForm.append('permitPhoto', new Blob(['test permit image'], { type: 'image/png' }), 'permit.png');
  const permitResponse = await request('/api/security/permits', {
    method: 'POST',
    headers: authHeaders(staff.token),
    body: permitForm
  });
  assert.equal(permitResponse.status, 201);
  const permit = await permitResponse.json();
  assert.equal(permit.vehicle_code, accessRecord.vehicle_code);
  const permitList = await (await request('/api/security/permits?status=expiring&search=XYZ', {
    headers: authHeaders(staff.token)
  })).json();
  assert.equal(permitList.length, 1);
  assert.equal(permitList[0].status, 'expiring');
  const vehicleLookup = await (await request(`/api/security/vehicles?plate=${encodeURIComponent('XYZ 987')}`, {
    headers: authHeaders(staff.token)
  })).json();
  assert.equal(vehicleLookup.vehicle_code, permit.vehicle_code);
  assert.equal(vehicleLookup.permits[0].driver_name, 'سائق تجريبي');
  assert.equal(vehicleLookup.access[0].members.length, 2);
  const codeLookup = await (await request(`/api/security/vehicles?plate=${encodeURIComponent(permit.vehicle_code)}`, {
    headers: authHeaders(staff.token)
  })).json();
  assert.equal(codeLookup.plate, 'XYZ 987');
  assert.equal((await (await request('/api/security/summary', {
    headers: authHeaders(staff.token)
  })).json()).expiring_permits, 1);
  const permitImage = await request(`/api/media/${permit.media_id}/preview`, { headers: authHeaders(staff.token) });
  assert.equal(permitImage.status, 200);
  assert.equal((await request(`/api/media/${permit.media_id}`, {
    method: 'DELETE',
    headers: authHeaders(staff.token)
  })).status, 409);

  const reportForm = new FormData();
  reportForm.append('title', 'ملاحظة عند البوابة');
  reportForm.append('category', 'ملاحظة');
  reportForm.append('location', 'البوابة الرئيسية');
  reportForm.append('details', 'تم توثيق الحالة بالصورة.');
  reportForm.append('reportPhoto', new Blob(['test report image'], { type: 'image/png' }), 'report.png');
  const reportResponse = await request('/api/security/reports', {
    method: 'POST',
    headers: authHeaders(staff.token),
    body: reportForm
  });
  assert.equal(reportResponse.status, 201);
  const report = await reportResponse.json();
  const reports = await (await request('/api/security/reports', {
    headers: authHeaders(staff.token)
  })).json();
  assert.equal(reports[0].title, 'ملاحظة عند البوابة');
  assert.equal((await request(`/api/media/${report.media_id}/preview`, {
    headers: authHeaders(staff.token)
  })).status, 200);

  const procedureForm = new FormData();
  procedureForm.append('title', 'جولة صباحية');
  procedureForm.append('category', 'جولة تفقدية');
  procedureForm.append('location', 'البوابة الرئيسية');
  procedureForm.append('details', 'تم التأكد من سلامة المدخل.');
  procedureForm.append('procedurePhoto', new Blob(['daily check image'], { type: 'image/png' }), 'daily.png');
  const procedureResponse = await request('/api/security/procedures', {
    method: 'POST',
    headers: authHeaders(staff.token),
    body: procedureForm
  });
  assert.equal(procedureResponse.status, 201);
  const procedure = await procedureResponse.json();
  assert.equal(procedure.created_by_name, 'Security Staff');
  const procedures = await (await request('/api/security/procedures', {
    headers: authHeaders(staff.token)
  })).json();
  assert.equal(procedures[0].title, 'جولة صباحية');
  assert.equal((await request(`/api/media/${procedure.media_id}`, {
    method: 'DELETE',
    headers: authHeaders(staff.token)
  })).status, 409);


  // Uploaded files are stored in the media store (Netlify Blobs in production), not on local disk.
  assert.ok(api.media.files.size >= 4);
  const audit = await (await request('/api/audit', { headers: authHeaders(staff.token) })).json();
  assert.ok(audit.some((entry) => entry.action === 'إضافة تصريح مركبة'));
  assert.match(audit[0].created_at, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
});
