// backend/tests/user.test.js
const request = require("supertest");
const app = require("../index"); // pastikan app diexport dari index.js

describe("User API", () => {
  it("should register a new user", async () => {
    const res = await request(app)
      .post("/api/register")
      .send({ email: "test@example.com", password: "123456" });
    expect(res.statusCode).toBe(201);
  });
});
