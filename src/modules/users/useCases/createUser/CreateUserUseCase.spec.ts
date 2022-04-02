import { InMemoryUsersRepository } from "../../repositories/in-memory/InMemoryUsersRepository";
import { IUsersRepository } from "../../repositories/IUsersRepository";
import { CreateUserError } from "./CreateUserError";
import { CreateUserUseCase } from "./CreateUserUseCase";

let usersRepository: IUsersRepository;
let createUserUseCase: CreateUserUseCase;

describe("CreateUserUseCase", () => {
  beforeEach(() => {
    usersRepository = new InMemoryUsersRepository();
    createUserUseCase = new CreateUserUseCase(usersRepository);
  });

  it("should be able to create a user", async () => {
    const response = await createUserUseCase.execute({
        name: "teste",
        email: "teste@gmail.com",
        password: "1234",
    });

    expect(response).toHaveProperty("id");
  });

  it("should not be able to create a duplicated user", async () => {
    await createUserUseCase.execute({
        name: "teste",
        email: "teste@gmail.com",
        password: "1234",
    });

    await expect(
      createUserUseCase.execute({
        name: "teste",
        email: "teste@gmail.com",
        password: "12345",
      })
    ).rejects.toBeInstanceOf(CreateUserError);
  });
});