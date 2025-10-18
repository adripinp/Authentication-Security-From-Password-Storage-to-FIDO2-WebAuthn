async function sendOtp(){
  const username = document.getElementById('otpUser').value;
  const otp = document.getElementById('otp').value;
  const res = await fetch('/capture-otp', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({username, otp})
  });
  document.getElementById('otpResult').textContent = JSON.stringify(await res.json(), null, 2);
}