import { IsString, IsNotEmpty } from 'class-validator';

export class SignOutAllDto {
  @IsString()
  @IsNotEmpty()
  access_token: string;

  @IsString()
  @IsNotEmpty()
  backend_token: string;
}
