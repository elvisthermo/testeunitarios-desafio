import { hash } from "bcryptjs";

import { InMemoryUsersRepository } from "../../repositories/in-memory/InMemoryUsersRepository";
import { IUsersRepository } from "../../repositories/IUsersRepository";
import { AuthenticateUserUseCase } from "./AuthenticateUserUseCase";
import { IncorrectEmailOrPasswordError } from "./IncorrectEmailOrPasswordError";

let usersRepository: IUsersRepository;
let authenticateUserUseCase: AuthenticateUserUseCase;

describe("AuthenticateUserUseCase", () => {
  beforeEach(() => {
    usersRepository = new InMemoryUsersRepository();
    authenticateUserUseCase = new AuthenticateUserUseCase(usersRepository);
  });

  it("should not be able to authenticate with a non-existent user", async () => {
    await expect(
      authenticateUserUseCase.execute({
        email: "non@existent.com",
        password: "non-existent",
      })
    ).rejects.toBeInstanceOf(IncorrectEmailOrPasswordError);
  });

  it("should not be able to authenticate with a wrong password", async () => {
    await usersRepository.create({
      email: "johndoe@exemple.com",
      name: "John Doe",
      password: await hash("1234", 8),
    });
    await expect(
      authenticateUserUseCase.execute({
        email: "johndoe@exemple.com",
        password: "wrong-password",
      })
    ).rejects.toBeInstanceOf(IncorrectEmailOrPasswordError);
  });

  it("should not be able to authenticate with a wrong email", async () => {
    await usersRepository.create({
      email: "johndoe@exemple.com",
      name: "John Doe",
      password: await hash("1234", 8),
    });

    await expect(
      authenticateUserUseCase.execute({
        email: "non@existent.com",
        password: "1234",
      })
    ).rejects.toBeInstanceOf(IncorrectEmailOrPasswordError);
  });
});