import { IsString, IsNotEmpty } from 'class-validator';

export class CheckSessionDto {
  @IsString()
  @IsNotEmpty()
  session_id: string;
}
